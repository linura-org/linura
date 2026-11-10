//! S18-4 read-only original NetworkManager / logind subject correlation.
//!
//! This is NOT Polkit approval, a native SecretAgent, secret transfer or effect
//! grant. The original Control process must derive these facts from actual
//! system-bus names and logind rather than from requestor-provided identities.
//! A mixed/vanished provider fails closed; a valid witness is not transferable.

use super::*;
use linura_core::{
    NetworkDeviceId, NetworkManagerEpoch, NetworkObjectKind, NetworkObservationId,
    NetworkProfileRevision,
};

const NM_NAME: &str = "org.freedesktop.NetworkManager";
const NM_ROOT: &str = "/org/freedesktop/NetworkManager";
const NM_INTERFACE: &str = "org.freedesktop.NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const NM_SETTINGS_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings";
const MAX_NATIVE_OBJECTS: usize = 128;
const MAX_OBSERVATION_AGE_US: u64 = 5_000_000;
const MAX_NATIVE_REPLY_BYTES: usize = 64 * 1024;

// SecurityOwner1's fixed nested wire scope. A typed value is correlation only:
// the native owner must attest the actual Control sender and current NM target.
type NetworkCredentialWire = (
    (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ),
    (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        u32,
        u64,
        u64,
        bool,
    ),
);

/// Typed but not independently authenticated until read through Control's
/// original native connection. Never contains PSK/EAP, profile settings, SSID,
/// BSSID, environment variables or an authorization token.
#[derive(Clone, Debug)]
pub struct NativeNetworkSubjectRequest {
    pub lock: SessionLockId,
    pub network: NetworkManagerEpoch,
    pub device: NetworkDeviceId,
    pub profile: NetworkProfileRevision,
    pub observation: NetworkObservationId,
    pub principal: PrincipalId,
    pub seat: String,
    pub credential_request: RequestId,
    pub credential_request_digest: ComponentDigest,
    pub credential_review_digest: ComponentDigest,
}

impl NativeNetworkSubjectRequest {
    fn bind_original_approval(&self, approval: &NativeApprovalRequest) -> Result<(), String> {
        // Do not authorize on a subject probe alone. Only the S18 network
        // credential challenge in the original Control connection is eligible.
        // This is restrictive correlation, NOT an execution/secret-agent permit.
        if approval.purpose != NativeApprovalPurpose::NetworkCredential
            || approval.transition.is_some()
            || approval.lock != self.lock
            || approval.principal != self.principal
            || approval.request != self.credential_request
            || approval.plan.as_str() != self.credential_request.as_str()
            || approval.request_digest != self.credential_request_digest
            || approval.review_digest != self.credential_review_digest
        {
            return Err(
                "native network approval is not the exact original Control challenge".into(),
            );
        }
        approval.wire().map(|_| ())
    }

    fn wire(&self, control_sender: &str) -> Result<NetworkCredentialWire, String> {
        if !unique_name(control_sender) {
            return Err("native original Control sender is invalid".into());
        }
        let resource = self.lock.resource_id().map_err(|error| error.to_string())?;
        Ok((
            (
                resource.as_str().to_owned(),
                self.principal.as_str().to_owned(),
                "operation:network.wifi.join".into(),
                self.credential_request.as_str().to_owned(),
                control_sender.to_owned(),
                self.network.bus().as_str().to_owned(),
                self.network.owner().as_str().to_owned(),
                self.seat.clone(),
            ),
            (
                self.device.object().native_path(),
                self.device.interface().as_str().to_owned(),
                self.profile.object().native_path(),
                self.profile.uuid().to_owned(),
                self.profile.settings_fingerprint().to_owned(),
                format!("sha256:{}", self.credential_request_digest),
                format!("sha256:{}", self.credential_review_digest),
                self.device.ifindex(),
                self.device.namespace_inode(),
                self.profile.revision_generation(),
                false, // The one-use S18-4 agent must never persist secrets.
            ),
        ))
    }

    fn validate(&self, now_us: u64) -> Result<(), String> {
        if self.lock.epoch().uid() == 0
            || self.principal.as_str() != format!("unix:uid:{}", self.lock.epoch().uid())
            || self.network.boot() != self.lock.epoch().boot()
            || self.seat.len() < 5
            || self.seat.len() > 32
            || !self.seat.starts_with("seat")
            || (self.seat.len() > 5 && self.seat.as_bytes()[4] == b'0')
            || !self.seat[4..].bytes().all(|b| b.is_ascii_digit())
            || self.device.object().kind() != NetworkObjectKind::Device
            || self.device.generation() != self.device.object().sequence()
            || self.profile.object().kind() != NetworkObjectKind::SettingsConnection
        {
            return Err("native network subject scope is not the exact local login".into());
        }
        self.network
            .require_same(self.device.epoch())
            .map_err(|_| "native network device epoch was replaced".to_owned())?;
        self.network
            .require_same(self.profile.epoch())
            .map_err(|_| "native network profile epoch was replaced".to_owned())?;
        self.observation
            .require_fresh(&self.network, now_us, MAX_OBSERVATION_AGE_US)
            .map_err(|_| "native network observation is stale or from another owner".to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeNetworkSubjectCorrelation {
    subject: NativeAuthenticationSubject,
    network: NetworkManagerEpoch,
    device_path: String,
    profile_path: String,
    seat: String,
}

impl NativeNetworkSubjectCorrelation {
    pub const fn subject(&self) -> &NativeAuthenticationSubject {
        &self.subject
    }

    pub const fn network(&self) -> &NetworkManagerEpoch {
        &self.network
    }

    pub fn device_path(&self) -> &str {
        &self.device_path
    }

    pub fn profile_path(&self) -> &str {
        &self.profile_path
    }

    pub fn seat(&self) -> &str {
        &self.seat
    }
}

fn require_network_manager_process(uid: u32, pid: u32) -> Result<(), String> {
    // NetworkManager may not be replaced by a foreign user service that
    // happens to own the well-known name. Root is necessary but never enough
    // to authorize a Linura effect or transfer a Polkit subject.
    if uid != 0 || pid <= 1 || pid > i32::MAX as u32 {
        return Err("native NetworkManager daemon credentials are not root-owned".into());
    }
    Ok(())
}

impl NativeSessionChannel {
    fn arm_original_network_agent(
        &self,
        request: &NativeNetworkSubjectRequest,
    ) -> Result<bool, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let identity = self.discover(request.lock.epoch().uid(), started)?;
        if identity.invocation != *request.lock.security_owner_invocation()
            || current_boot()? != *request.lock.epoch().boot()
        {
            return Err("native network agent refers to a replaced owner or boot".into());
        }
        let sender = self
            .connection
            .unique_name()
            .ok_or("native original Control connection has no unique name")?;
        let wire = request.wire(sender.as_str())?;
        let (armed,): (bool,) = self
            .call_with_budget(
                &identity.unique_name,
                ENDPOINT,
                INTERFACE,
                "ArmNetworkCredential",
                &(wire,),
                owner_reply_budget(started.elapsed())?,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native network agent arm result is malformed".to_owned())?;
        if started.elapsed() >= crate::bus::PROBE_BUDGET {
            return Err("native network agent handoff exceeded its original deadline".into());
        }
        self.revalidate(&identity, started)?;
        Ok(armed)
    }

    fn cancel_original_network_agent(&self, uid: u32) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let identity = self.discover(uid, started)?;
        self.call(
            &identity.unique_name,
            ENDPOINT,
            INTERFACE,
            "CancelNetworkCredential",
            &(),
            started,
        )?;
        self.revalidate(&identity, started)
    }

    pub(super) fn native_network_epoch(
        &self,
        started: Instant,
    ) -> Result<NetworkManagerEpoch, String> {
        let bus: String = self
            .bus_call("GetId", &(), started)?
            .body()
            .deserialize()
            .map_err(|_| "native system bus instance reply is malformed".to_owned())?;
        let owner: String = self
            .bus_call("GetNameOwner", &(NM_NAME,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native NetworkManager owner reply is malformed".to_owned())?;
        let (uid, pid) = self.connection_credentials(&owner, started)?;
        require_network_manager_process(uid, pid)?;
        Ok(NetworkManagerEpoch::new(
            current_boot()?,
            linura_core::SystemBusInstanceId::new(bus)
                .map_err(|_| "native system bus identity is invalid".to_owned())?,
            linura_core::NetworkManagerOwner::new(owner)
                .map_err(|_| "native NetworkManager owner is invalid".to_owned())?,
        ))
    }

    pub(super) fn native_network_seat(
        &self,
        lock: &SessionLockId,
        wanted_seat: &str,
        started: Instant,
    ) -> Result<String, String> {
        let owner: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native network logind owner is unavailable".to_owned())?;
        if self.connection_credentials(&owner, started)?.0 != 0 {
            return Err("native network logind owner is not root".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &owner,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSession",
                &(lock.epoch().session_id(),),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native network login session is unavailable".to_owned())?;
        if !path
            .as_str()
            .starts_with("/org/freedesktop/login1/session/")
            || path.as_str().len() > 256
        {
            return Err("native network session object is malformed".into());
        }
        let facts = self.properties(
            &owner,
            path.as_str(),
            "org.freedesktop.login1.Session",
            started,
        )?;
        // The S17-qualified check rejects root, remote, inactive, non-Wayland
        // and replaced login leaders before binding the seat property.
        let _leader = authentication_leader(lock, &facts)?;
        let seat_value = facts
            .get("Seat")
            .ok_or("native network seat property is absent")?
            .try_clone()
            .map_err(|_| "native network seat property is malformed".to_owned())?;
        let (seat, seat_path): (String, OwnedObjectPath) = zbus::zvariant::Value::from(seat_value)
            .try_into()
            .map_err(|_| "native network seat identity has wrong type".to_owned())?;
        if seat != wanted_seat
            || seat_path.as_str() != format!("/org/freedesktop/login1/seat/{seat}")
        {
            return Err("native network request came from a foreign seat".into());
        }
        let fresh_owner: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native network logind owner recheck failed".to_owned())?;
        if fresh_owner != owner {
            return Err("native logind owner changed during network attestation".into());
        }
        Ok(seat)
    }

    fn native_network_identity_facts(
        &self,
        request: &NativeNetworkSubjectRequest,
        started: Instant,
    ) -> Result<(), String> {
        let owner = request.network.owner().as_str();
        // The Settings-wide VersionId fences ABA, including an update which
        // restores the same visible settings. It is not a per-profile counter.
        let settings = self.properties(owner, NM_SETTINGS_PATH, NM_SETTINGS_INTERFACE, started)?;
        let version: u64 = property(&settings, "VersionId")?;
        if version == 0 || version != request.profile.revision_generation() {
            return Err("native network profile settings generation was replaced".into());
        }

        // A native object path alone is not a device. Correlate the current
        // interface and kernel netns/ifindex, matching the S18-2 observer.
        let device = self.properties(
            owner,
            &request.device.object().native_path(),
            "org.freedesktop.NetworkManager.Device",
            started,
        )?;
        let interface: &str = property(&device, "Interface")?;
        if interface != request.device.interface().as_str()
            || request.device.generation() != request.device.object().sequence()
        {
            return Err("native network device path or kernel generation differs".into());
        }
        let netns = fs::metadata("/proc/self/ns/net")
            .map_err(|_| "native network namespace cannot be observed")?
            .ino();
        let path = format!("/sys/class/net/{interface}/ifindex");
        let ifindex: u32 = fs::read_to_string(path)
            .map_err(|_| "native network kernel interface was replaced")?
            .trim()
            .parse()
            .map_err(|_| "native network kernel ifindex is malformed")?;
        let second_ns = fs::metadata("/proc/self/ns/net")
            .map_err(|_| "native network namespace vanished")?
            .ino();
        if netns == 0
            || netns != request.device.namespace_inode()
            || netns != second_ns
            || ifindex == 0
            || ifindex != request.device.ifindex()
        {
            return Err("native network kernel interface identity differs".into());
        }
        Ok(())
    }

    fn native_network_inventory(
        &self,
        epoch: &NetworkManagerEpoch,
        device: &str,
        profile: &str,
        started: Instant,
    ) -> Result<(), String> {
        let reply = self.call(
            epoch.owner().as_str(),
            NM_ROOT,
            NM_INTERFACE,
            "GetDevices",
            &(),
            started,
        )?;
        if reply.body().len() > MAX_NATIVE_REPLY_BYTES {
            return Err("native device inventory exceeds decoder limit".into());
        }
        let paths: Vec<OwnedObjectPath> = reply
            .body()
            .deserialize()
            .map_err(|_| "native device inventory cannot be decoded".to_owned())?;
        if paths.len() > MAX_NATIVE_OBJECTS
            || paths.iter().filter(|path| path.as_str() == device).count() != 1
        {
            return Err("native network device is absent or ambiguous".into());
        }
        let reply = self.call(
            epoch.owner().as_str(),
            NM_SETTINGS_PATH,
            NM_SETTINGS_INTERFACE,
            "ListConnections",
            &(),
            started,
        )?;
        if reply.body().len() > MAX_NATIVE_REPLY_BYTES {
            return Err("native profile inventory exceeds decoder limit".into());
        }
        let paths: Vec<OwnedObjectPath> = reply
            .body()
            .deserialize()
            .map_err(|_| "native profile inventory cannot be decoded".to_owned())?;
        if paths.len() > MAX_NATIVE_OBJECTS
            || paths.iter().filter(|path| path.as_str() == profile).count() != 1
        {
            return Err("native network profile is absent or ambiguous".into());
        }
        Ok(())
    }

    /// Authenticate the original subject and arm ONE purpose-bound native
    /// SecretAgent on the same attested Control-role connection. The spent
    /// Polkit proof cannot be relayed as an NM operation permit. Following a
    /// slow interactive exchange the short-lived observation may expire; in
    /// that case deny rather than extending the review or replaying it.
    pub fn authenticate_original_network_credential(
        &self,
        network: &NativeNetworkSubjectRequest,
        approval: &NativeApprovalRequest,
        budget: Duration,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        network.bind_original_approval(approval)?;
        let original = self.observe_original_network_subject(network)?;
        match self.arm_approval(approval) {
            Ok(true) => {}
            Ok(false) => {
                // Refusal does not attest ownership of a pending native
                // challenge. Do not cancel an unrelated S17 approval.
                return Err("native original network challenge was refused".into());
            }
            Err(_) => {
                // A missing/lost reply is ambiguous. Cancel rather than
                // attempting the same original request again.
                let _ = self.cancel_approval(network.lock.epoch().uid());
                return Err("native original network challenge outcome is unknown".into());
            }
        }
        let authenticated = self.authenticate_approval(approval, budget);
        if let Err(error) = authenticated {
            let _ = self.cancel_approval(network.lock.epoch().uid());
            return Err(error);
        }
        let before_consumption = self.observe_original_network_subject(network);
        if before_consumption.as_ref() != Ok(&original) {
            let _ = self.cancel_approval(network.lock.epoch().uid());
            return Err("native network identity became stale during Polkit interaction".into());
        }
        if !matches!(self.consume_approval(approval), Ok(true)) {
            let _ = self.cancel_approval(network.lock.epoch().uid());
            return Err("native one-use network authentication was not consumed".into());
        }
        if self.observe_original_network_subject(network).as_ref() != Ok(&original) {
            // Proof is already spent. Refuse any use and require a new source
            // observation and distinct Control review, never re-arm/replay.
            return Err("native network identity changed after authentication consumption".into());
        }
        if !matches!(self.arm_original_network_agent(network), Ok(true)) {
            let _ = self.cancel_original_network_agent(network.lock.epoch().uid());
            return Err("native original NetworkManager SecretAgent registration failed".into());
        }
        if self.observe_original_network_subject(network).as_ref() != Ok(&original) {
            // A registered agent is NOT authorization. Revoke on any late
            // session, owner, device or profile change. No replay after ambiguity.
            let _ = self.cancel_original_network_agent(network.lock.epoch().uid());
            return Err("native network identity changed after agent registration".into());
        }
        Ok(())
    }

    /// Read-only original subject correlation. This method has no Polkit
    /// CheckAuthorization, no SecretAgent registration and no dispatch. It
    /// verifies a *current membership*, not profile revision CAS or physical
    /// connectivity; the eventual secret-agent must freshly recheck both.
    pub fn observe_original_network_subject(
        &self,
        request: &NativeNetworkSubjectRequest,
    ) -> Result<NativeNetworkSubjectCorrelation, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let now_us = boot_ms()?
            .checked_mul(1000)
            .ok_or("native boot clock overflow")?;
        request.validate(now_us)?;
        let epoch = self.native_network_epoch(started)?;
        request
            .network
            .require_same(&epoch)
            .map_err(|_| "native NetworkManager epoch has changed".to_owned())?;
        let subject = self.authentication_subject(&request.lock)?;
        let seat = self.native_network_seat(&request.lock, &request.seat, started)?;
        let device_path = request.device.object().native_path();
        let profile_path = request.profile.object().native_path();
        self.native_network_inventory(&epoch, &device_path, &profile_path, started)?;
        self.native_network_identity_facts(request, started)?;
        self.native_network_inventory(&epoch, &device_path, &profile_path, started)?;
        self.native_network_identity_facts(request, started)?;
        if self.native_network_epoch(started)? != epoch
            || self.authentication_subject(&request.lock)? != subject
            || self.native_network_seat(&request.lock, &request.seat, started)? != seat
            || started.elapsed() >= crate::bus::PROBE_BUDGET
        {
            return Err("native network subject or provider changed during attestation".into());
        }
        Ok(NativeNetworkSubjectCorrelation {
            subject,
            network: epoch,
            device_path,
            profile_path,
            seat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        NetworkInterfaceName, NetworkManagerOwner, NetworkObjectId, SecurityOwnerInvocationId,
        SessionEpoch, SystemBusInstanceId,
    };

    #[test]
    fn only_the_actual_root_networkmanager_process_may_own_the_native_name() {
        assert!(require_network_manager_process(0, 215).is_ok());
        for (uid, pid) in [(1000, 215), (0, 0), (0, 1), (0, u32::MAX)] {
            assert!(require_network_manager_process(uid, pid).is_err());
        }
    }

    fn sample() -> NativeNetworkSubjectRequest {
        let boot = BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        let bus = SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        let network = NetworkManagerEpoch::new(
            boot.clone(),
            bus,
            NetworkManagerOwner::new(":1.48")
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
        );
        let device = NetworkDeviceId::new(
            network.clone(),
            NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/3",
            )
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            1024,
            3,
            NetworkInterfaceName::new("wlan0")
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            3,
        )
        .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        let profile = NetworkProfileRevision::new(
            network.clone(),
            NetworkObjectId::from_path(
                NetworkObjectKind::SettingsConnection,
                "/org/freedesktop/NetworkManager/Settings/9",
            )
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            "10203040-5060-7080-90ab-cdef12345678",
            17,
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        )
        .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        NativeNetworkSubjectRequest {
            lock: SessionLockId::new(
                SessionEpoch::new(boot, 1000, "2", 42)
                    .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
                SecurityOwnerInvocationId::new("98765432-1234-4567-89ab-0123456789ab")
                    .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
                1,
            )
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            network: network.clone(),
            device,
            profile,
            observation: NetworkObservationId::new(network, 4, 1_000_000)
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            principal: PrincipalId::new("unix:uid:1000")
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            seat: "seat0".into(),
            credential_request: RequestId::new("request:v010:network-credential:fixture")
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            credential_request_digest: ComponentDigest::from_bytes([1_u8; 32]),
            credential_review_digest: ComponentDigest::from_bytes([2_u8; 32]),
        }
    }

    fn approval(request: &NativeNetworkSubjectRequest) -> NativeApprovalRequest {
        NativeApprovalRequest {
            lock: request.lock.clone(),
            transition: None,
            principal: request.principal.clone(),
            request: request.credential_request.clone(),
            plan: PlanId::new(request.credential_request.as_str())
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
            request_digest: request.credential_request_digest,
            observation_digest: ComponentDigest::from_bytes([3_u8; 32]),
            review_digest: request.credential_review_digest,
            purpose: NativeApprovalPurpose::NetworkCredential,
        }
    }

    #[test]
    fn original_network_challenge_is_exact_not_a_transferable_polkit_subject() {
        let request = sample();
        let valid = approval(&request);
        assert!(request.bind_original_approval(&valid).is_ok());
        let mut wrong = valid.clone();
        wrong.purpose = NativeApprovalPurpose::Unlock;
        assert!(request.bind_original_approval(&wrong).is_err());
        wrong = valid.clone();
        wrong.principal = PrincipalId::new("unix:uid:0")
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        assert!(request.bind_original_approval(&wrong).is_err());
        wrong = valid.clone();
        wrong.request = RequestId::new("request:v010:network-credential:other")
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        assert!(request.bind_original_approval(&wrong).is_err());
        wrong = valid.clone();
        wrong.review_digest = ComponentDigest::from_bytes([4_u8; 32]);
        assert!(request.bind_original_approval(&wrong).is_err());
        wrong = valid.clone();
        wrong.request_digest = ComponentDigest::from_bytes([5_u8; 32]);
        assert!(request.bind_original_approval(&wrong).is_err());
    }

    #[test]
    fn exact_subject_never_accepts_foreign_uid_owner_or_stale_epoch() {
        let request = sample();
        assert!(request.validate(1_020_000).is_ok());
        let mut changed = request.clone();
        changed.principal = PrincipalId::new("unix:uid:0")
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        assert!(changed.validate(1_020_000).is_err());
        changed = request.clone();
        changed.seat = "seat/0".into();
        assert!(changed.validate(1_020_000).is_err());
        changed = request.clone();
        changed.seat = "seat00".into();
        assert!(changed.validate(1_020_000).is_err());
        changed = request.clone();
        changed.seat = "seat01".into();
        assert!(changed.validate(1_020_000).is_err());
        changed = request.clone();
        changed.network = NetworkManagerEpoch::new(
            request.network.boot().clone(),
            request.network.bus().clone(),
            NetworkManagerOwner::new(":1.49")
                .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}")),
        );
        assert!(changed.validate(1_020_000).is_err());
        changed = request.clone();
        changed.observation = NetworkObservationId::new(request.network.clone(), 1, 9_000_000)
            .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        assert!(changed.validate(1_020_000).is_err());
        changed = request.clone();
        assert!(changed.validate(6_000_001).is_err());
        changed = request.clone();
        changed.device = NetworkDeviceId::new(
            request.network.clone(),
            request.device.object().clone(),
            request.device.namespace_inode(),
            request.device.ifindex(),
            request.device.interface().clone(),
            request.device.generation() + 1,
        )
        .unwrap_or_else(|error| unreachable!("typed fixture: {error:?}"));
        assert!(changed.validate(1_020_000).is_err());
    }
}
