//! S18-5: narrow, trusted native Wi-Fi scan effect adapter.
//!
//! This adapter does not authorize effects. Its only dispatch entry consumes
//! Control's non-cloneable AuthorizedEffect after the durable handoff. It has
//! no client D-Bus, nmcli, arbitrary method or settings-map forwarding.
//! RequestScan is deliberately unavailable until Control's separate event
//! transaction route and actual native qualification are approved.

use super::*;
use linura_core::{NetworkDeviceId, NetworkManagerEpoch, NetworkObjectKind, NetworkObservationId};
use linura_provider_sdk::{
    EffectDescriptor, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;

const NM_ROOT: &str = "/org/freedesktop/NetworkManager";
const NM_INTERFACE: &str = "org.freedesktop.NetworkManager";
const NM_WIFI: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const NM_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const MAX_SCAN_DEVICES: usize = 128;
const MAX_RFKILL_DEVICES: usize = 32;
const MIN_SCAN_INTERVAL_MS: u64 = 30_000;
const MAX_OBSERVATION_AGE_US: u64 = 5_000_000;
const MAX_NATIVE_WIFI_REPLY_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWifiScanScope {
    pub lock: SessionLockId,
    pub principal: PrincipalId,
    pub network: NetworkManagerEpoch,
    pub device: NetworkDeviceId,
    pub observation: NetworkObservationId,
    pub seat: String,
    pub baseline_last_scan_boot_ms: i64,
    /// A known original attempt must be durably accounted for in Control.
    /// A missing journal is never interpreted as permission for an attempt.
    pub durable_attempt_fenced: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWifiScanSample {
    pub network: NetworkManagerEpoch,
    pub device: NetworkDeviceId,
    pub last_scan_boot_ms: i64,
    pub scanning: bool,
    pub sampled_boot_us: u64,
}

/// An independently reread native post-dispatch sample, not a D-Bus method
/// acknowledgement, cached AP inventory, or authorization token. Exact
/// owner/device and original-session binding are rechecked at sampling time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWifiScanCompletion {
    pub network: NetworkManagerEpoch,
    pub device: NetworkDeviceId,
    pub last_scan_boot_ms: u64,
    pub sampled_boot_us: u64,
}

/// A new LastScan under the same owner is necessary, but not by itself a
/// cryptographic proof of causal attribution if a foreign process also scans.
/// The caller must retain and validate the original durable attempt binding.
fn correlated_scan_completion(
    last_scan: i64,
    scanning: bool,
    baseline: i64,
    attempted_at_boot_ms: u64,
    sampled_boot_ms: u64,
) -> Result<Option<u64>, String> {
    if attempted_at_boot_ms == 0 || baseline < -1 || last_scan < -1 ||
        sampled_boot_ms < attempted_at_boot_ms ||
        sampled_boot_ms.saturating_sub(attempted_at_boot_ms) > 15_000
    {
        return Err("native Wi-Fi scan completion clock/epoch is unsupported".into());
    }
    let Some(scan_ms) = u64::try_from(last_scan).ok() else {
        return Ok(None);
    };
    if scan_ms > sampled_boot_ms {
        return Err("native Wi-Fi scan completed in the future".into());
    }
    if scanning || scan_ms < attempted_at_boot_ms ||
        (baseline >= 0 && scan_ms <= baseline as u64)
    {
        return Ok(None);
    }
    Ok(Some(scan_ms))
}

impl NativeWifiScanScope {
    pub fn validate(
        &self,
        effect: &EffectDescriptor,
        binding: &ExecutionBinding,
        now_boot_us: u64,
    ) -> Result<(), String> {
        if self.lock.epoch().uid() == 0
            || self.principal.as_str() != format!("unix:uid:{}", self.lock.epoch().uid())
            || self.lock.epoch().boot() != self.network.boot()
            || self.network.require_same(self.device.epoch()).is_err()
            || self.device.object().kind() != NetworkObjectKind::Device
            || self.device.generation() != self.device.object().sequence()
            || !valid_seat(&self.seat)
            || !self.durable_attempt_fenced
            || self.baseline_last_scan_boot_ms < -1
        {
            return Err("scan target is not a durably fenced, original native login/device".into());
        }
        self.observation
            .require_fresh(&self.network, now_boot_us, MAX_OBSERVATION_AGE_US)
            .map_err(|_| "scan target lacks a fresh exact native observation".to_owned())?;
        if effect.provider.as_str() != "networkmanager"
            || effect.resource.as_str()
                != format!("networkmanager:wifi:{}", self.device.interface().as_str())
            || effect.operation != "request-wifi-scan"
            || effect.canonical_payload.as_slice() != b"scan_requested=true\n"
            || binding.validate_for(effect).is_err()
        {
            return Err("scan effect differs from Control's sealed exact native operation".into());
        }
        Ok(())
    }
}

fn valid_seat(seat: &str) -> bool {
    let Some(number) = seat.strip_prefix("seat") else {
        return false;
    };
    !number.is_empty()
        && number.len() <= 10
        && (number.len() == 1 || !number.starts_with('0'))
        && number.bytes().all(|value| value.is_ascii_digit())
}

fn check_radio_state(
    manager: &Properties,
    device: &Properties,
    wifi: &Properties,
    boot_ms: u64,
    expected_last_scan: i64,
) -> Result<i64, String> {
    let networking: bool = property(manager, "NetworkingEnabled")?;
    let enabled: bool = property(manager, "WirelessEnabled")?;
    let hardware: bool = property(manager, "WirelessHardwareEnabled")?;
    let kind: u32 = property(device, "DeviceType")?;
    let managed: bool = property(device, "Managed")?;
    let state: u32 = property(device, "State")?;
    let scanning: bool = property(wifi, "Scanning")?;
    let last_scan: i64 = property(wifi, "LastScan")?;
    if !networking
        || !enabled
        || !hardware
        || kind != 2
        || !managed
        || !matches!(state, 30 | 100)
        || scanning
    {
        return Err("native Wi-Fi device/radio is unavailable, blocked or already scanning".into());
    }
    if last_scan != expected_last_scan
        || last_scan < -1
        || (last_scan >= 0
            && u64::try_from(last_scan)
                .is_ok_and(|ms| ms > boot_ms || boot_ms.saturating_sub(ms) < MIN_SCAN_INTERVAL_MS))
    {
        return Err("native scan generation changed, is malformed or is rate limited".into());
    }
    Ok(last_scan)
}

fn kernel_wifi_rfkill_clear() -> Result<(), String> {
    // Conservative global WLAN rfkill, never a guessed adapter-specific unblock.
    // A kernel without independently readable rfkill cannot qualify this path.
    let iter =
        fs::read_dir("/sys/class/rfkill").map_err(|_| "native rfkill inventory is unavailable")?;
    let mut found = false;
    let mut count = 0_usize;
    for item in iter {
        let item = item.map_err(|_| "native rfkill inventory changed")?;
        count = count.checked_add(1).ok_or("rfkill inventory overflow")?;
        if count > MAX_RFKILL_DEVICES {
            return Err("native rfkill inventory exceeds its bound".into());
        }
        let name = item.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("rfkill")
            || !name["rfkill".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            return Err("native rfkill identity is not canonical".into());
        }
        let base = item.path();
        let kind =
            fs::read_to_string(base.join("type")).map_err(|_| "native rfkill type disappeared")?;
        if kind.trim() != "wlan" {
            continue;
        }
        found = true;
        let soft = fs::read_to_string(base.join("soft"))
            .map_err(|_| "native rfkill soft state disappeared")?;
        let hard = fs::read_to_string(base.join("hard"))
            .map_err(|_| "native rfkill hardware state disappeared")?;
        if soft.trim() != "0" || hard.trim() != "0" {
            return Err("native WLAN rfkill blocks an active scan".into());
        }
    }
    if !found {
        return Err("native WLAN rfkill identity is unproven".into());
    }
    Ok(())
}

impl NativeSessionChannel {
    fn native_wifi_scan_seat(
        &self,
        scope: &NativeWifiScanScope,
        started: Instant,
    ) -> Result<(), String> {
        let _subject = self.authentication_subject(&scope.lock)?;
        let owner: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native scan logind owner is malformed".to_owned())?;
        if self.connection_credentials(&owner, started)?.0 != 0 {
            return Err("native scan logind is not root".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &owner,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSession",
                &(scope.lock.epoch().session_id(),),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native scan logind session vanished".to_owned())?;
        if path.as_str().len() > 256
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err("native scan session object is not canonical".into());
        }
        let facts = self.properties(
            &owner,
            path.as_str(),
            "org.freedesktop.login1.Session",
            started,
        )?;
        let _leader = authentication_leader(&scope.lock, &facts)?;
        let seat_value = facts
            .get("Seat")
            .ok_or("native scan seat is absent")?
            .try_clone()
            .map_err(|_| "native scan seat is malformed".to_owned())?;
        let (seat, path): (String, OwnedObjectPath) = zbus::zvariant::Value::from(seat_value)
            .try_into()
            .map_err(|_| "native scan seat has the wrong type".to_owned())?;
        let fresh: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native scan logind generation changed".to_owned())?;
        if seat != scope.seat
            || path.as_str() != format!("/org/freedesktop/login1/seat/{seat}")
            || fresh != owner
        {
            return Err("native scan seat or logind owner was replaced".into());
        }
        Ok(())
    }

    pub fn native_wifi_scan_sample(
        &self,
        scope: &NativeWifiScanScope,
    ) -> Result<NativeWifiScanSample, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        scope
            .network
            .require_same(&self.native_network_epoch(started)?)
            .map_err(|_| "native NetworkManager owner/bus/boot changed".to_owned())?;
        self.native_wifi_scan_seat(scope, started)?;
        let owner = scope.network.owner().as_str();
        let path = scope.device.object().native_path();
        let reply = self.call(owner, NM_ROOT, NM_INTERFACE, "GetDevices", &(), started)?;
        if reply.body().len() > MAX_NATIVE_WIFI_REPLY_BYTES {
            return Err("native scan device list exceeds decoder budget".into());
        }
        let devices: Vec<OwnedObjectPath> = reply
            .body()
            .deserialize()
            .map_err(|_| "native scan device list is malformed".to_owned())?;
        if devices.len() > MAX_SCAN_DEVICES
            || devices.iter().filter(|item| item.as_str() == path).count() != 1
        {
            return Err("native Wi-Fi device is missing or ambiguous".into());
        }
        let manager = self.properties(owner, NM_ROOT, NM_INTERFACE, started)?;
        let device = self.properties(owner, &path, NM_DEVICE, started)?;
        let wifi = self.properties(owner, &path, NM_WIFI, started)?;
        let interface: &str = property(&device, "Interface")?;
        if interface != scope.device.interface().as_str()
            || scope.device.generation() != scope.device.object().sequence()
        {
            return Err("native scan device generation/interface changed".into());
        }
        let namespace = fs::metadata("/proc/self/ns/net")
            .map_err(|_| "network namespace vanished")?
            .ino();
        let filename = format!("/sys/class/net/{interface}/ifindex");
        let ifindex: u32 = fs::read_to_string(&filename)
            .map_err(|_| "network ifindex vanished")?
            .trim()
            .parse()
            .map_err(|_| "network ifindex is malformed")?;
        let second_namespace = fs::metadata("/proc/self/ns/net")
            .map_err(|_| "network namespace changed")?
            .ino();
        let second_ifindex: u32 = fs::read_to_string(&filename)
            .map_err(|_| "network device changed")?
            .trim()
            .parse()
            .map_err(|_| "network ifindex is malformed")?;
        if namespace == 0
            || namespace != scope.device.namespace_inode()
            || namespace != second_namespace
            || ifindex != scope.device.ifindex()
            || ifindex == 0
            || ifindex != second_ifindex
        {
            return Err("native kernel Wi-Fi identity changed".into());
        }
        let now_boot_us = boot_ms()?
            .checked_mul(1000)
            .ok_or("native boot clock overflow")?;
        scope
            .observation
            .require_fresh(&scope.network, now_boot_us, MAX_OBSERVATION_AGE_US)
            .map_err(|_| "original scan observation is stale".to_owned())?;
        check_radio_state(
            &manager,
            &device,
            &wifi,
            now_boot_us / 1000,
            scope.baseline_last_scan_boot_ms,
        )?;
        kernel_wifi_rfkill_clear()?;
        if self.native_network_epoch(started)? != scope.network {
            return Err("NetworkManager owner/bus/boot changed mid-scan preflight".into());
        }
        self.native_wifi_scan_seat(scope, started)?;
        Ok(NativeWifiScanSample {
            network: scope.network.clone(),
            device: scope.device.clone(),
            last_scan_boot_ms: scope.baseline_last_scan_boot_ms,
            scanning: false,
            sampled_boot_us: now_boot_us,
        })
    }

    /// Separate fresh native read for a *spent* durable event attempt.
    /// A returned observation is only a source-bound correlation: it cannot
    /// complete a Control transaction or issue permission without the exact
    /// attempt journal and a qualified exclusive-attribution policy.
    pub fn observe_sealed_wifi_scan_completion(
        &self,
        scope: &NativeWifiScanScope,
        attempted_at_boot_ms: u64,
    ) -> Result<Option<NativeWifiScanCompletion>, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        scope.network.require_same(&self.native_network_epoch(started)?)
            .map_err(|_| "native NetworkManager owner/bus/boot changed".to_owned())?;
        self.native_wifi_scan_seat(scope, started)?;
        let owner = scope.network.owner().as_str();
        let device_path = scope.device.object().native_path();
        let inventory = self.call(owner, NM_ROOT, NM_INTERFACE, "GetDevices", &(), started)?;
        if inventory.body().len() > MAX_NATIVE_WIFI_REPLY_BYTES {
            return Err("native scan completion inventory exceeds bounded wire budget".into());
        }
        let devices: Vec<OwnedObjectPath> = inventory.body().deserialize()
            .map_err(|_| "native scan completion device inventory is malformed".to_owned())?;
        if devices.len() > MAX_SCAN_DEVICES ||
            devices.iter().filter(|item| item.as_str() == device_path).count() != 1
        {
            return Err("native scan completion device changed or disappeared".into());
        }
        let manager = self.properties(owner, NM_ROOT, NM_INTERFACE, started)?;
        let device = self.properties(owner, &device_path, NM_DEVICE, started)?;
        let wifi = self.properties(owner, &device_path, NM_WIFI, started)?;
        let interface: &str = property(&device, "Interface")?;
        if interface != scope.device.interface().as_str() ||
            scope.device.generation() != scope.device.object().sequence() ||
            property::<u32>(&device, "DeviceType")? != 2 ||
            !property::<bool>(&device, "Managed")? ||
            !property::<bool>(&manager, "NetworkingEnabled")? ||
            !property::<bool>(&manager, "WirelessEnabled")? ||
            !property::<bool>(&manager, "WirelessHardwareEnabled")?
        {
            return Err("native scan completion device or radio was replaced/disabled".into());
        }
        let namespace = fs::metadata("/proc/self/ns/net").map_err(|_| "scan namespace vanished")?.ino();
        let filename = format!("/sys/class/net/{interface}/ifindex");
        let ifindex: u32 = fs::read_to_string(&filename).map_err(|_| "scan interface vanished")?
            .trim().parse().map_err(|_| "scan interface index is malformed")?;
        if namespace != scope.device.namespace_inode() || ifindex != scope.device.ifindex() || ifindex == 0 ||
            fs::metadata("/proc/self/ns/net").map_err(|_| "scan namespace vanished")?.ino() != namespace ||
            fs::read_to_string(&filename).map_err(|_| "scan interface vanished")?.trim() != ifindex.to_string()
        {
            return Err("native scan completion kernel device changed".into());
        }
        kernel_wifi_rfkill_clear()?;
        let last_scan: i64 = property(&wifi, "LastScan")?;
        let scanning: bool = property(&wifi, "Scanning")?;
        let now_ms = boot_ms()?;
        let completed = correlated_scan_completion(last_scan, scanning, scope.baseline_last_scan_boot_ms,
            attempted_at_boot_ms, now_ms)?;
        if self.native_network_epoch(started)? != scope.network {
            return Err("native scan completion source owner changed".into());
        }
        self.native_wifi_scan_seat(scope, started)?;
        Ok(completed.map(|last_scan_boot_ms| NativeWifiScanCompletion {
            network: scope.network.clone(),
            device: scope.device.clone(),
            last_scan_boot_ms,
            sampled_boot_us: now_ms.saturating_mul(1_000),
        }))
    }

    /// Native transport, never an authorization. Only Authority1's trusted
    /// composition root may call this after consuming a non-cloneable
    /// Control AuthorizedEffect and durably spending an event attempt.
    /// ExecutionBinding alone cannot grant permission. No D-Bus method
    /// forwards this API, and S18's production Control route remains denied.
    pub fn dispatch_sealed_wifi_scan(
        &self,
        effect: EffectDescriptor,
        binding: ExecutionBinding,
        scope: &NativeWifiScanScope,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let now = boot_ms()?
            .checked_mul(1000)
            .ok_or("native clock overflow")?;
        scope.validate(&effect, &binding, now)?;
        self.native_wifi_scan_sample(scope)?;
        // Any failure after the one-use authority handoff is ambiguous.
        // Never retry this RequestScan, even if the bus reports an error.
        let call = self.call(
            scope.network.owner().as_str(),
            &scope.device.object().native_path(),
            NM_WIFI,
            "RequestScan",
            &(HashMap::<String, OwnedValue>::new(),),
            Instant::now(),
        );
        let disposition = match call {
            Ok(reply) if reply.body().is_empty() => ExecutionDisposition::Dispatched,
            Ok(_) | Err(_) => ExecutionDisposition::Indeterminate,
        };
        ExecutionOutcome::new(
            disposition,
            binding.dispatch_digest,
            "one-use native Wi-Fi RequestScan attempt; independent verification pending",
        )
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        BootId, NetworkInterfaceName, NetworkManagerOwner, NetworkObjectId, PrincipalId,
        ProviderId, ResourceId, SystemBusInstanceId,
    };
    use linura_provider_sdk::ComponentDigest;

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
    }

    fn fixture() -> (NativeWifiScanScope, EffectDescriptor, ExecutionBinding) {
        let boot = ok(BootId::new("abcd1234-1234-4567-89ab-0123456789ab"));
        let epoch = NetworkManagerEpoch::new(
            boot.clone(),
            ok(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            ok(NetworkManagerOwner::new(":1.48")),
        );
        let device = ok(NetworkDeviceId::new(
            epoch.clone(),
            ok(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/8",
            )),
            12456,
            7,
            ok(NetworkInterfaceName::new("wlan0")),
            8,
        ));
        let lock = ok(SessionLockId::new(
            linura_core::SessionEpoch::new(boot, 1000, "2", 42)
                .unwrap_or_else(|error| unreachable!("{error:?}")),
            ok(SecurityOwnerInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            1,
        ));
        let scope = NativeWifiScanScope {
            lock,
            principal: ok(PrincipalId::new("unix:uid:1000")),
            network: epoch.clone(),
            device,
            observation: ok(NetworkObservationId::new(epoch, 4, 100_000_000)),
            seat: "seat0".into(),
            baseline_last_scan_boot_ms: -1,
            durable_attempt_fenced: true,
        };
        let effect = ok(EffectDescriptor::new(
            ok(ProviderId::new("networkmanager")),
            ok(ResourceId::new("networkmanager:wifi:wlan0")),
            "request-wifi-scan",
            b"scan_requested=true\n".to_vec(),
        ));
        let binding = ok(ExecutionBinding::new(
            "txn:wifi:fixture",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        (scope, effect, binding)
    }

    #[test]
    fn exact_sealed_dispatch_shape_and_original_login_are_required() {
        let (mut s, effect, binding) = fixture();
        assert!(s.validate(&effect, &binding, 101_000_000).is_ok());
        s.durable_attempt_fenced = false;
        assert!(s.validate(&effect, &binding, 101_000_000).is_err());
        s.durable_attempt_fenced = true;
        s.seat = "seat00".into();
        assert!(s.validate(&effect, &binding, 101_000_000).is_err());
        s.seat = "seat0".into();
        assert!(s.validate(&effect, &binding, 106_000_001).is_err());
        let mut wrong = effect.clone();
        wrong.operation = "run-nmcli".into();
        assert!(s.validate(&wrong, &binding, 101_000_000).is_err());
        wrong = effect.clone();
        wrong.canonical_payload = b"scan_requested=true\nssids=secret\n".to_vec();
        assert!(s.validate(&wrong, &binding, 101_000_000).is_err());
    }

    #[test]
    fn independent_scan_completion_rejects_cached_ambiguous_and_future_samples() {
        assert_eq!(correlated_scan_completion(105_100, false, 80_000, 105_000, 105_500).unwrap(), Some(105_100));
        assert_eq!(correlated_scan_completion(80_000, false, 80_000, 105_000, 105_500).unwrap(), None);
        assert_eq!(correlated_scan_completion(105_100, true, 80_000, 105_000, 105_500).unwrap(), None);
        assert_eq!(correlated_scan_completion(104_999, false, 80_000, 105_000, 105_500).unwrap(), None);
        assert!(correlated_scan_completion(105_600, false, 80_000, 105_000, 105_500).is_err());
        assert!(correlated_scan_completion(120_000, false, 80_000, 105_000, 121_000).is_err());
        assert!(correlated_scan_completion(105_100, false, -2, 105_000, 105_500).is_err());
        assert!(correlated_scan_completion(105_100, false, 80_000, 105_000, 104_900).is_err());
    }

    #[test]
    fn native_facts_require_radio_managed_and_prevent_spam() {
        let mut manager = Properties::new();
        manager.insert("NetworkingEnabled".into(), OwnedValue::from(true));
        manager.insert("WirelessEnabled".into(), OwnedValue::from(true));
        manager.insert("WirelessHardwareEnabled".into(), OwnedValue::from(true));
        let mut device = Properties::new();
        device.insert("DeviceType".into(), OwnedValue::from(2_u32));
        device.insert("Managed".into(), OwnedValue::from(true));
        device.insert("State".into(), OwnedValue::from(30_u32));
        let mut wifi = Properties::new();
        wifi.insert("Scanning".into(), OwnedValue::from(false));
        wifi.insert("LastScan".into(), OwnedValue::from(-1_i64));
        assert!(check_radio_state(&manager, &device, &wifi, 100_000, -1).is_ok());
        wifi.insert("LastScan".into(), OwnedValue::from(99_000_i64));
        assert!(check_radio_state(&manager, &device, &wifi, 100_000, 99_000).is_err());
        wifi.insert("LastScan".into(), OwnedValue::from(40_000_i64));
        assert!(check_radio_state(&manager, &device, &wifi, 100_000, 40_000).is_ok());
        manager.insert("WirelessEnabled".into(), OwnedValue::from(false));
        assert!(check_radio_state(&manager, &device, &wifi, 100_000, 40_000).is_err());
        manager.insert("WirelessEnabled".into(), OwnedValue::from(true));
        wifi.insert("Scanning".into(), OwnedValue::from(true));
        assert!(check_radio_state(&manager, &device, &wifi, 100_000, 40_000).is_err());
    }
}
