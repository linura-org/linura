//! Read-only session facts. Neither LockedHint nor service acknowledgement is
//! evidence of a secure compositor lock. Screen coverage is a separate fact from
//! the security-owning locker and must be verified by Control before mutation.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use linura_core::{
    BootId, Capability, CapabilityId, ProviderId, ResourceId, SessionEpoch, SessionTransition,
    SessionTransitionId,
};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::{capability, next_sequence, now_unix_ms, provider_id, snapshot_property};

pub const LOGIND_SESSION_PROVIDER: &str = "logind";
pub const LOGIND_SESSION_CAPABILITY: &str = "session.epoch.observe";
pub const LOGIND_POWER_CAPABILITY: &str = "session.power.observe";
pub const LOGIND_POWER_CONDITIONS_CAPABILITY: &str = "session.power.conditions.observe";
pub const LOGIND_TRANSITION_CAPABILITY: &str = "session.transition.observe";
const SERVICE: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const NATIVE_CALL_TIMEOUT: Duration = Duration::from_millis(750);
const VALID_FOR_MS: u64 = 2_000;
const MAX_SESSIONS: usize = 16;
type SessionRow = (String, u32, String, String, OwnedObjectPath);
type InhibitorRow = (String, String, String, String, u32, u32);
const MAX_INHIBITORS: usize = 32;
// Native replies may contain user-controlled inhibitor descriptions or remote
// session labels. Bound the serialized body before allocating decoded strings,
// arrays or property maps, independently of the row/field limits below. zbus's
// separate transport frame bound still applies before this adapter receives it.
const MAX_NATIVE_REPLY_BODY_BYTES: usize = 64 * 1024;

pub struct LogindSessionObserver {
    connection: Connection,
    sequence: AtomicU64,
}

impl Debug for LogindSessionObserver {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogindSessionObserver")
            .finish_non_exhaustive()
    }
}

impl LogindSessionObserver {
    pub fn connect() -> Result<Self, ProviderError> {
        // Neither DBUS_SYSTEM_BUS_ADDRESS nor an unauthenticated bus daemon may
        // choose our observation authority. Verify the connected kernel peer
        // before the independently deadline-bounded D-Bus authentication.
        let stream = crate::platform_discovery::connect_unix_with_deadline(
            Path::new("/run/dbus/system_bus_socket"),
            NATIVE_CALL_TIMEOUT,
            "session observation system bus",
        )
        .map_err(|_| {
            ProviderError::Unavailable(
                "trusted system bus connection is unavailable or timed out".into(),
            )
        })?;
        let credentials = rustix::net::sockopt::socket_peercred(&stream).map_err(|_| {
            ProviderError::Unavailable("cannot authenticate system bus kernel peer".into())
        })?;
        if credentials.uid.as_raw() != 0 {
            return Err(ProviderError::InvalidState(
                "system bus kernel peer is not root".into(),
            ));
        }
        let builder = zbus::connection::Builder::async_io_unix_stream(stream)
            .method_timeout(NATIVE_CALL_TIMEOUT);
        let connection = crate::platform_discovery::build_dbus_connection_with_deadline(
            builder,
            "session observation system bus",
        )
        .map_err(|_| {
            ProviderError::Unavailable(
                "trusted system bus authentication is unavailable or timed out".into(),
            )
        })?;
        Ok(Self {
            connection,
            sequence: AtomicU64::new(0),
        })
    }

    fn bus(&self) -> Result<Proxy<'_>, ProviderError> {
        Proxy::new(
            &self.connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(bus_error)
    }

    fn trusted_owner(&self) -> Result<String, ProviderError> {
        let bus = self.bus()?;
        let owner: String = bus.call("GetNameOwner", &(SERVICE,)).map_err(bus_error)?;
        let uid: u32 = bus
            .call("GetConnectionUnixUser", &(owner.as_str(),))
            .map_err(bus_error)?;
        validate_owner(&owner, uid)?;
        Ok(owner)
    }

    fn require_same_owner(&self, expected: &str) -> Result<(), ProviderError> {
        let owner: String = self
            .bus()?
            .call("GetNameOwner", &(SERVICE,))
            .map_err(bus_error)?;
        if owner != expected {
            return Err(ProviderError::Unavailable(
                "logind ownership changed during observation".into(),
            ));
        }
        Ok(())
    }

    fn manager<'a>(&'a self, owner: &'a str) -> Result<Proxy<'a>, ProviderError> {
        Proxy::new(&self.connection, owner, MANAGER_PATH, MANAGER_INTERFACE).map_err(bus_error)
    }

    fn snapshot(
        &self,
        owner: &str,
        path: &str,
        boot: BootId,
    ) -> Result<SessionSnapshot, ProviderError> {
        let properties = self.properties(owner, path, SESSION_INTERFACE)?;
        SessionSnapshot::from_properties(&properties, boot)
    }

    fn properties(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
    ) -> Result<HashMap<String, OwnedValue>, ProviderError> {
        let proxy = Proxy::new(
            &self.connection,
            owner,
            path,
            "org.freedesktop.DBus.Properties",
        )
        .map_err(bus_error)?;
        let reply = proxy
            .call_method("GetAll", &(interface,))
            .map_err(bus_error)?;
        require_reply_bound(&reply)?;
        reply.body().deserialize().map_err(bus_error)
    }

    fn power_attributes(
        &self,
        owner: &str,
        expected: &SessionEpoch,
        observed_at: u64,
    ) -> Result<BTreeMap<String, ObservedValue>, ProviderError> {
        self.require_power_query_scope(owner, expected, observed_at)?;
        let manager = self.manager(owner)?;
        let mut attributes = BTreeMap::new();
        for (method, key) in [
            ("CanSuspend", "suspend_availability"),
            ("CanReboot", "reboot_availability"),
            ("CanPowerOff", "power_off_availability"),
        ] {
            require_probe_deadline(observed_at)?;
            let availability: String = bounded_manager_reply(&manager, method)?
                .body()
                .deserialize()
                .map_err(bus_error)?;
            validate_power_availability(&availability)?;
            attributes.insert(key.into(), ObservedValue::Text(availability));
        }
        attributes.extend(self.power_conditions_attributes(owner, expected, observed_at)?);
        // Can* includes native permissions for its actual bus subject. Never
        // relabel a root/system-service result as the owning user's permission.
        self.require_power_query_scope(owner, expected, observed_at)?;
        attributes.insert(
            "permission_query_principal".into(),
            ObservedValue::Text(format!("unix:uid:{}", expected.uid())),
        );
        attributes.insert(
            "permission_query_session_epoch".into(),
            ObservedValue::Text(
                expected
                    .resource_id()
                    .map_err(invalid_epoch)?
                    .as_str()
                    .into(),
            ),
        );
        Ok(attributes)
    }

    // Conditions carry no caller-sensitive Can* result. Control combines
    // these with a separate original-session permission observation; this
    // adapter never aggregates facts from other providers.
    fn power_conditions_attributes(
        &self,
        owner: &str,
        expected: &SessionEpoch,
        observed_at: u64,
    ) -> Result<BTreeMap<String, ObservedValue>, ProviderError> {
        let manager = self.manager(owner)?;
        let mut attributes = BTreeMap::new();
        require_probe_deadline(observed_at)?;
        let properties = self.properties(owner, MANAGER_PATH, MANAGER_INTERFACE)?;
        attributes.insert(
            "preparing_for_sleep".into(),
            ObservedValue::Bool(snapshot_property(&properties, "PreparingForSleep")?),
        );
        attributes.insert(
            "preparing_for_shutdown".into(),
            ObservedValue::Bool(snapshot_property(&properties, "PreparingForShutdown")?),
        );
        let delay_max_us: u64 = snapshot_property(&properties, "InhibitDelayMaxUSec")?;
        if delay_max_us == 0 || delay_max_us > 60_000_000 {
            return Err(ProviderError::Unsupported(
                "native sleep inhibition deadline is unsupported".into(),
            ));
        }
        attributes.insert(
            "inhibit_delay_max_us".into(),
            ObservedValue::U64(delay_max_us),
        );
        require_probe_deadline(observed_at)?;
        let inhibitors: Vec<InhibitorRow> = bounded_manager_reply(&manager, "ListInhibitors")?
            .body()
            .deserialize()
            .map_err(bus_error)?;
        attributes.extend(inhibitor_counts(&inhibitors)?);
        require_probe_deadline(observed_at)?;
        let sessions: Vec<SessionRow> = bounded_manager_reply(&manager, "ListSessions")?
            .body()
            .deserialize()
            .map_err(bus_error)?;
        validate_session_rows(&sessions)?;
        let mut other_user_sessions = 0_u64;
        let mut found_expected = false;
        for (id, uid, _account, _seat, path) in sessions {
            require_probe_deadline(observed_at)?;
            let session = self.snapshot(owner, path.as_str(), expected.boot().clone())?;
            if session.epoch.session_id() != id || session.epoch.uid() != uid {
                return Err(ProviderError::InvalidState(
                    "native power session enumeration drifted".into(),
                ));
            }
            if session.epoch == *expected {
                found_expected = true;
            } else if session_blocks_machine_power(&session, expected)? {
                // Include remote, inactive and same-uid sessions on other seats:
                // machine power loss affects more than the currently active seat.
                other_user_sessions += 1;
            }
        }
        if !found_expected {
            return Err(ProviderError::InvalidState(
                "native power session disappeared".into(),
            ));
        }
        attributes.insert(
            "other_user_session_count".into(),
            ObservedValue::U64(other_user_sessions),
        );
        Ok(attributes)
    }

    fn require_power_query_scope(
        &self,
        owner: &str,
        expected: &SessionEpoch,
        observed_at: u64,
    ) -> Result<(), ProviderError> {
        require_probe_deadline(observed_at)?;
        let own_name = self.connection.unique_name().ok_or_else(|| {
            ProviderError::Unavailable("native power query has no authenticated bus subject".into())
        })?;
        let bus = self.bus()?;
        let uid: u32 = bus
            .call("GetConnectionUnixUser", &(own_name.as_str(),))
            .map_err(bus_error)?;
        let pid: u32 = bus
            .call("GetConnectionUnixProcessID", &(own_name.as_str(),))
            .map_err(bus_error)?;
        require_probe_deadline(observed_at)?;
        if uid != expected.uid() || pid == 0 {
            return Err(ProviderError::Unsupported(
                "native power permission query does not belong to the requested owner".into(),
            ));
        }
        let path: OwnedObjectPath = self
            .manager(owner)?
            .call("GetSessionByPID", &(pid,))
            .map_err(|_| {
                ProviderError::Unsupported(
                    "native power permission query is outside the requested login session".into(),
                )
            })?;
        if path.as_str().len() > 256
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err(ProviderError::Unsupported(
                "native power permission query has an unsupported session handle".into(),
            ));
        }
        let own_session = self.snapshot(owner, path.as_str(), expected.boot().clone())?;
        require_power_query_identity(expected, uid, &own_session.epoch)
    }

    fn epoch_present(
        &self,
        owner: &str,
        expected: &SessionEpoch,
        current: &BootId,
    ) -> Result<bool, ProviderError> {
        if expected.boot() != current {
            return Ok(false);
        }
        let path: OwnedObjectPath = match self
            .manager(owner)?
            .call("GetSession", &(expected.session_id(),))
        {
            Ok(path) => path,
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.login1.NoSuchSession" =>
            {
                return Ok(false);
            }
            Err(error) => return Err(bus_error(error)),
        };
        if path.as_str().len() > 256
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err(ProviderError::InvalidState(
                "native transition session handle is unsupported".into(),
            ));
        }
        // A recycled session name with another creation generation establishes
        // absence of the ORIGINAL epoch, not permission to affect its successor.
        Ok(self.snapshot(owner, path.as_str(), current.clone())?.epoch == *expected)
    }

    /// One bounded transition sample. `None` means only that the exact expected
    /// native suspend cycle crossed this sample; it supplies no authoritative
    /// facts or completion evidence. Control may independently sample again
    /// within its existing verification budget. All other failures remain errors.
    pub fn observe_transition_if_settled(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<Option<ObservationEnvelope>, ProviderError> {
        if capability.as_str() != LOGIND_TRANSITION_CAPABILITY {
            return Err(ProviderError::Unsupported(
                "native transition observation capability is not supported".into(),
            ));
        }
        let transition = SessionTransitionId::from_resource(resource).map_err(|_| {
            ProviderError::Unsupported("native transition identity is not canonical".into())
        })?;
        let Some(sample) = sample_transition(&mut LogindTransitionProbe(self), &transition)? else {
            return Ok(None);
        };
        Ok(Some(ObservationEnvelope {
            provider: self.observer_id(),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: sample.observed_at_unix_ms,
            valid_for_ms: VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: sample.attributes,
        }))
    }
}

// Private native mechanisms make the complete one-sample ordering testable.
// This interface carries no scheduling, retry policy or observation authority.
trait TransitionProbe {
    fn now_unix_ms(&mut self) -> Result<u64, ProviderError>;
    fn current_boot(&mut self) -> Result<BootId, ProviderError>;
    fn trusted_owner(&mut self) -> Result<String, ProviderError>;
    fn epoch_present(
        &mut self,
        owner: &str,
        expected: &SessionEpoch,
        current: &BootId,
    ) -> Result<bool, ProviderError>;
    fn suspend_success_count(&mut self) -> Result<u64, ProviderError>;
    fn suspend_test_mode(&mut self) -> Result<String, ProviderError>;
    fn preparing_for_sleep(&mut self, owner: &str) -> Result<bool, ProviderError>;
    fn require_same_owner(&mut self, expected: &str) -> Result<(), ProviderError>;
}

struct LogindTransitionProbe<'a>(&'a LogindSessionObserver);

impl TransitionProbe for LogindTransitionProbe<'_> {
    fn now_unix_ms(&mut self) -> Result<u64, ProviderError> {
        now_unix_ms()
    }
    fn current_boot(&mut self) -> Result<BootId, ProviderError> {
        current_boot()
    }
    fn trusted_owner(&mut self) -> Result<String, ProviderError> {
        self.0.trusted_owner()
    }
    fn epoch_present(
        &mut self,
        owner: &str,
        expected: &SessionEpoch,
        current: &BootId,
    ) -> Result<bool, ProviderError> {
        self.0.epoch_present(owner, expected, current)
    }
    fn suspend_success_count(&mut self) -> Result<u64, ProviderError> {
        suspend_success_count()
    }
    fn suspend_test_mode(&mut self) -> Result<String, ProviderError> {
        suspend_test_mode()
    }
    fn preparing_for_sleep(&mut self, owner: &str) -> Result<bool, ProviderError> {
        let properties = self.0.properties(owner, MANAGER_PATH, MANAGER_INTERFACE)?;
        snapshot_property(&properties, "PreparingForSleep")
    }
    fn require_same_owner(&mut self, expected: &str) -> Result<(), ProviderError> {
        self.0.require_same_owner(expected)
    }
}

struct TransitionSample {
    observed_at_unix_ms: u64,
    attributes: BTreeMap<String, ObservedValue>,
}

fn sample_transition(
    probe: &mut impl TransitionProbe,
    transition: &SessionTransitionId,
) -> Result<Option<TransitionSample>, ProviderError> {
    let observed_at_unix_ms = probe.now_unix_ms()?;
    let boot = probe.current_boot()?;
    let owner = probe.trusted_owner()?;
    require_probe_deadline_at(observed_at_unix_ms, probe.now_unix_ms()?)?;
    let epoch = transition.lock().epoch();
    let present = probe.epoch_present(&owner, epoch, &boot)?;
    require_probe_deadline_at(observed_at_unix_ms, probe.now_unix_ms()?)?;
    let mut attributes = BTreeMap::from([
        (
            "current_boot_id".into(),
            ObservedValue::Text(boot.as_str().into()),
        ),
        ("target_epoch_present".into(), ObservedValue::Bool(present)),
    ]);
    let mut pending_cycle = false;
    if let SessionTransition::Suspend {
        successful_cycles_before,
    } = transition.transition()
        && epoch.boot() == &boot
    {
        // Linux's completed counter and disabled debug mode, never an awake
        // hint. Read both test-mode samples even when the counter has changed.
        let before = probe.suspend_success_count()?;
        let test_before = probe.suspend_test_mode()?;
        require_probe_deadline_at(observed_at_unix_ms, probe.now_unix_ms()?)?;
        let preparing = probe.preparing_for_sleep(&owner)?;
        let after = probe.suspend_success_count()?;
        let test_after = probe.suspend_test_mode()?;
        if test_before != "none" || test_after != "none" {
            return Err(ProviderError::Unsupported(
                "native suspend debug mode is unknown or enabled".into(),
            ));
        }
        if before != after {
            if !present
                || before != successful_cycles_before
                || successful_cycles_before.checked_add(1) != Some(after)
            {
                return Err(unsettled_transition_error());
            }
            pending_cycle = true;
        }
        attributes.insert("preparing_for_sleep".into(), ObservedValue::Bool(preparing));
        attributes.insert(
            "successful_suspend_cycles".into(),
            ObservedValue::U64(before),
        );
        attributes.insert("suspend_test_mode".into(), ObservedValue::Text(test_before));
    }
    require_probe_deadline_at(observed_at_unix_ms, probe.now_unix_ms()?)?;
    if present != probe.epoch_present(&owner, epoch, &boot)? {
        return Err(ProviderError::InvalidState(
            "native transition epoch changed during observation".into(),
        ));
    }
    require_same_boot(&boot, &probe.current_boot()?)?;
    probe.require_same_owner(&owner)?;
    require_probe_deadline_at(observed_at_unix_ms, probe.now_unix_ms()?)?;
    if pending_cycle {
        // Discard the entire mixed sample only after identity and its original
        // deadline are revalidated. It never acquires a sequence or freshness.
        return Ok(None);
    }
    Ok(Some(TransitionSample {
        observed_at_unix_ms,
        attributes,
    }))
}

fn unsettled_transition_error() -> ProviderError {
    ProviderError::InvalidState("native suspend state changed during observation".into())
}

fn require_power_query_identity(
    expected: &SessionEpoch,
    query_uid: u32,
    query_epoch: &SessionEpoch,
) -> Result<(), ProviderError> {
    if query_uid == 0 || query_uid != expected.uid() || query_epoch != expected {
        return Err(ProviderError::Unsupported(
            "native power permission query differs from the exact requested session".into(),
        ));
    }
    Ok(())
}

fn session_blocks_machine_power(
    session: &SessionSnapshot,
    expected: &SessionEpoch,
) -> Result<bool, ProviderError> {
    if session.epoch == *expected {
        return Ok(false);
    }
    match session.session_class.as_str() {
        // A closing session remains live until native enumeration removes it.
        "user" | "user-early" | "user-incomplete" | "user-light" | "user-early-light"
        | "greeter" | "lock-screen" => Ok(true),
        "manager" | "manager-early" | "background" | "background-light" => {
            Ok(session.epoch.uid() != expected.uid())
        }
        _ => Err(ProviderError::Unsupported(
            "native shared-session class is unknown".into(),
        )),
    }
}

impl Observer for LogindSessionObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(LOGIND_SESSION_PROVIDER)
    }

    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        matches!(
            capability.as_str(),
            LOGIND_SESSION_CAPABILITY
                | LOGIND_POWER_CAPABILITY
                | LOGIND_TRANSITION_CAPABILITY
                | LOGIND_POWER_CONDITIONS_CAPABILITY
        )
    }

    fn requires_live_health_preflight(&self) -> bool {
        false
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        [
            LOGIND_SESSION_CAPABILITY,
            LOGIND_POWER_CAPABILITY,
            LOGIND_TRANSITION_CAPABILITY,
            LOGIND_POWER_CONDITIONS_CAPABILITY,
        ]
        .into_iter()
        .map(|id| {
            capability(
                id,
                LOGIND_SESSION_PROVIDER,
                health.availability,
                health.reason.clone(),
            )
        })
        .collect()
    }

    fn health(&self) -> ProviderHealth {
        match self.trusted_owner() {
            Ok(_) => ProviderHealth {
                provider: self.observer_id(),
                availability: ProviderAvailability::Available,
                reason: None,
            },
            Err(error) => ProviderHealth {
                provider: self.observer_id(),
                availability: ProviderAvailability::Unavailable,
                reason: Some(error.to_string()),
            },
        }
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        let observed_at = now_unix_ms()?;
        let boot = current_boot()?;
        let owner = self.trusted_owner()?;
        // Bind all native calls to the unique root-owned service, not a moving
        // well-known name. ListSessions supplies handles only inside this adapter.
        let rows: Vec<SessionRow> = bounded_manager_reply(&self.manager(&owner)?, "ListSessions")?
            .body()
            .deserialize()
            .map_err(bus_error)?;
        validate_session_rows(&rows)?;
        let mut resources = BTreeSet::new();
        for (id, uid, _account_name, _seat, path) in rows {
            require_probe_deadline(observed_at)?;
            let snapshot = self.snapshot(&owner, path.as_str(), boot.clone())?;
            if snapshot.epoch.session_id() != id || snapshot.epoch.uid() != uid {
                return Err(ProviderError::InvalidState(
                    "logind enumeration identity changed during observation".into(),
                ));
            }
            if !resources.insert(snapshot.epoch.resource_id().map_err(invalid_epoch)?) {
                return Err(ProviderError::InvalidState(
                    "logind returned a duplicate session epoch".into(),
                ));
            }
        }
        require_same_boot(&boot, &current_boot()?)?;
        self.require_same_owner(&owner)?;
        require_probe_deadline(observed_at)?;
        Ok(resources.into_iter().collect())
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "logind observation capability is not supported".into(),
            ));
        }
        if capability.as_str() == LOGIND_TRANSITION_CAPABILITY {
            // Planning/query callers still require one complete authoritative
            // envelope. Only the native post-dispatch verifier consumes None.
            return self
                .observe_transition_if_settled(resource, capability)?
                .ok_or_else(unsettled_transition_error);
        }
        let expected = SessionEpoch::from_resource(resource).map_err(invalid_epoch)?;
        let observed_at_unix_ms = now_unix_ms()?;
        let boot = current_boot()?;
        require_same_boot(expected.boot(), &boot)?;
        let owner = self.trusted_owner()?;
        let manager = self.manager(&owner)?;
        let path: OwnedObjectPath = manager
            .call("GetSession", &(expected.session_id(),))
            .map_err(bus_error)?;
        let snapshot = self.snapshot(&owner, path.as_str(), boot.clone())?;
        require_same_epoch(&expected, &snapshot.epoch)?;
        let power = if capability.as_str() == LOGIND_POWER_CAPABILITY {
            Some(self.power_attributes(&owner, &expected, observed_at_unix_ms)?)
        } else if capability.as_str() == LOGIND_POWER_CONDITIONS_CAPABILITY {
            Some(self.power_conditions_attributes(&owner, &expected, observed_at_unix_ms)?)
        } else {
            None
        };

        // Re-resolve and independently re-read immutable identity after the
        // property snapshot. A removed/recreated id never inherits old approval.
        let resolved: OwnedObjectPath = manager
            .call("GetSession", &(expected.session_id(),))
            .map_err(bus_error)?;
        if resolved != path {
            return Err(ProviderError::InvalidState(
                "logind session handle changed during observation".into(),
            ));
        }
        let fresh = self.snapshot(&owner, resolved.as_str(), boot.clone())?;
        require_same_epoch(&expected, &fresh.epoch)?;
        require_same_boot(&boot, &current_boot()?)?;
        self.require_same_owner(&owner)?;
        if now_unix_ms()?
            .checked_sub(observed_at_unix_ms)
            .is_none_or(|elapsed| elapsed >= VALID_FOR_MS)
        {
            return Err(ProviderError::Unavailable(
                "logind observation expired while probing current identity".into(),
            ));
        }
        let mut attributes = fresh.attributes();
        if let Some(power) = power {
            attributes.extend(power);
        }
        Ok(ObservationEnvelope {
            provider: self.observer_id(),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms,
            valid_for_ms: VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes,
        })
    }
}

fn require_reply_bound(reply: &zbus::Message) -> Result<(), ProviderError> {
    if reply.body().len() > MAX_NATIVE_REPLY_BODY_BYTES {
        return Err(ProviderError::InvalidState(
            "native session reply exceeds its decoding bound".into(),
        ));
    }
    Ok(())
}

fn bounded_manager_reply(proxy: &Proxy<'_>, method: &str) -> Result<zbus::Message, ProviderError> {
    let reply = proxy.call_method(method, &()).map_err(bus_error)?;
    require_reply_bound(&reply)?;
    Ok(reply)
}

fn require_probe_deadline(observed_at: u64) -> Result<(), ProviderError> {
    require_probe_deadline_at(observed_at, now_unix_ms()?)
}

fn require_probe_deadline_at(observed_at: u64, now: u64) -> Result<(), ProviderError> {
    if now
        .checked_sub(observed_at)
        .is_none_or(|elapsed| elapsed >= VALID_FOR_MS)
    {
        Err(ProviderError::Unavailable(
            "native session observation deadline expired".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_power_availability(availability: &str) -> Result<(), ProviderError> {
    if matches!(availability, "yes" | "no" | "challenge" | "na") {
        Ok(())
    } else {
        Err(ProviderError::Unsupported(
            "native power availability is unknown".into(),
        ))
    }
}

fn inhibitor_counts(
    rows: &[InhibitorRow],
) -> Result<BTreeMap<String, ObservedValue>, ProviderError> {
    if rows.len() > MAX_INHIBITORS {
        return Err(ProviderError::InvalidState(
            "native inhibitor enumeration exceeds its bound".into(),
        ));
    }
    let mut sleep_block = 0;
    let mut sleep_delay = 0;
    let mut shutdown_block = 0;
    let mut shutdown_delay = 0;
    for (what, who, why, mode, _uid, pid) in rows {
        if what.is_empty()
            || what.len() > 256
            || who.len() > 512
            || why.len() > 512
            || *pid == 0
            || !matches!(mode.as_str(), "block" | "block-weak" | "delay")
        {
            return Err(ProviderError::Unsupported(
                "native inhibitor state is unknown or unbounded".into(),
            ));
        }
        let mut kinds = BTreeSet::new();
        for kind in what.split(':') {
            if !matches!(
                kind,
                "shutdown"
                    | "sleep"
                    | "idle"
                    | "handle-power-key"
                    | "handle-reboot-key"
                    | "handle-suspend-key"
                    | "handle-hibernate-key"
                    | "handle-lid-switch"
            ) || !kinds.insert(kind)
            {
                return Err(ProviderError::Unsupported(
                    "native inhibitor kind is unknown or duplicated".into(),
                ));
            }
        }
        let delay = mode == "delay";
        if kinds.contains("sleep") {
            if delay {
                sleep_delay += 1;
            } else {
                sleep_block += 1;
            }
        }
        if kinds.contains("shutdown") {
            if delay {
                shutdown_delay += 1;
            } else {
                shutdown_block += 1;
            }
        }
    }
    // No account names, descriptions, PIDs, transport handles or raw diagnostics
    // escape. Availability and counts remain observation, never OS permission.
    Ok(BTreeMap::from([
        ("sleep_block_count".into(), ObservedValue::U64(sleep_block)),
        ("sleep_delay_count".into(), ObservedValue::U64(sleep_delay)),
        (
            "shutdown_block_count".into(),
            ObservedValue::U64(shutdown_block),
        ),
        (
            "shutdown_delay_count".into(),
            ObservedValue::U64(shutdown_delay),
        ),
    ]))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionSnapshot {
    epoch: SessionEpoch,
    session_type: String,
    session_class: String,
    state: String,
    seat: String,
    active: bool,
    remote: bool,
    locked_hint: bool,
    leader: u32,
}

impl SessionSnapshot {
    fn from_properties(
        properties: &HashMap<String, OwnedValue>,
        boot: BootId,
    ) -> Result<Self, ProviderError> {
        let id: String = snapshot_property(properties, "Id")?;
        let (uid, _user_path): (u32, OwnedObjectPath) = snapshot_property(properties, "User")?;
        let timestamp: u64 = snapshot_property(properties, "TimestampMonotonic")?;
        let (seat, _seat_path): (String, OwnedObjectPath) = snapshot_property(properties, "Seat")?;
        let session_type: String = snapshot_property(properties, "Type")?;
        let session_class: String = snapshot_property(properties, "Class")?;
        let state: String = snapshot_property(properties, "State")?;
        for value in [&seat, &session_type, &session_class, &state] {
            if value.len() > 64
                || value
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
            {
                return Err(ProviderError::InvalidState(
                    "logind session label is not a bounded native identifier".into(),
                ));
            }
        }
        if session_type.is_empty()
            || session_class.is_empty()
            || !matches!(state.as_str(), "opening" | "online" | "active" | "closing")
        {
            return Err(ProviderError::InvalidState(
                "logind session state is unsupported or unknown".into(),
            ));
        }
        Ok(Self {
            epoch: SessionEpoch::new(boot, uid, id, timestamp).map_err(invalid_epoch)?,
            session_type,
            session_class,
            state,
            seat,
            active: snapshot_property(properties, "Active")?,
            remote: snapshot_property(properties, "Remote")?,
            locked_hint: snapshot_property(properties, "LockedHint")?,
            leader: snapshot_property(properties, "Leader")?,
        })
    }

    fn attributes(self) -> BTreeMap<String, ObservedValue> {
        BTreeMap::from([
            (
                "boot_id".into(),
                ObservedValue::Text(self.epoch.boot().as_str().into()),
            ),
            (
                "session_id".into(),
                ObservedValue::Text(self.epoch.session_id().into()),
            ),
            (
                "uid".into(),
                ObservedValue::U64(u64::from(self.epoch.uid())),
            ),
            (
                "created_monotonic_us".into(),
                ObservedValue::U64(self.epoch.created_monotonic_us()),
            ),
            (
                "session_type".into(),
                ObservedValue::Text(self.session_type),
            ),
            (
                "session_class".into(),
                ObservedValue::Text(self.session_class),
            ),
            ("state".into(), ObservedValue::Text(self.state)),
            ("seat".into(), ObservedValue::Text(self.seat)),
            ("active".into(), ObservedValue::Bool(self.active)),
            ("remote".into(), ObservedValue::Bool(self.remote)),
            ("locked_hint".into(), ObservedValue::Bool(self.locked_hint)),
            (
                "leader_present".into(),
                ObservedValue::Bool(self.leader != 0),
            ),
        ])
    }
}

fn current_boot() -> Result<BootId, ProviderError> {
    let mut bytes = Vec::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .and_then(|file| file.take(38).read_to_end(&mut bytes))
        .map_err(|_| ProviderError::Unavailable("cannot read the kernel boot identity".into()))?;
    parse_boot_bytes(&bytes)
}

fn read_power_fact(path: &str, maximum: u64) -> Result<Vec<u8>, ProviderError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| {
        ProviderError::Unsupported("required native suspend fact is unavailable".into())
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| {
        ProviderError::InvalidState("native suspend metadata is unavailable".into())
    })?;
    let filesystem = rustix::fs::fstatfs(&file).map_err(|_| {
        ProviderError::InvalidState("native suspend filesystem is unavailable".into())
    })?;
    // Linux SYSFS_MAGIC. A regular temporary file with a plausible counter is
    // not an authoritative native fact, even if supplied by the same UID/root.
    if filesystem.f_type != 0x6265_6572
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProviderError::InvalidState(
            "native suspend fact is not trusted sysfs".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::Unavailable("native suspend fact could not be read".into()))?;
    if bytes.len() as u64 > maximum {
        return Err(ProviderError::InvalidState(
            "native suspend fact exceeds its bound".into(),
        ));
    }
    Ok(bytes)
}

fn suspend_success_count() -> Result<u64, ProviderError> {
    decode_suspend_success(&read_power_fact("/sys/power/suspend_stats/success", 21)?)
}

fn decode_suspend_success(bytes: &[u8]) -> Result<u64, ProviderError> {
    let failure =
        || ProviderError::InvalidState("native suspend generation is noncanonical".into());
    let text = std::str::from_utf8(bytes)
        .map_err(|_| failure())?
        .strip_suffix('\n')
        .ok_or_else(failure)?;
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(failure());
    }
    text.parse().map_err(|_| failure())
}

fn suspend_test_mode() -> Result<String, ProviderError> {
    decode_suspend_test_mode(&read_power_fact("/sys/power/pm_test", 256)?)
}

fn decode_suspend_test_mode(bytes: &[u8]) -> Result<String, ProviderError> {
    let failure =
        || ProviderError::Unsupported("native suspend debug mode is unknown or enabled".into());
    let text = std::str::from_utf8(bytes)
        .map_err(|_| failure())?
        .strip_suffix('\n')
        .ok_or_else(failure)?;
    let mut seen = BTreeSet::new();
    let mut selected = false;
    for field in text.split_ascii_whitespace() {
        if field == "[none]" {
            if selected {
                return Err(failure());
            }
            selected = true;
        } else if !matches!(
            field,
            "freezer" | "devices" | "platform" | "processors" | "core"
        ) {
            return Err(failure());
        }
        if !seen.insert(field) {
            return Err(failure());
        }
    }
    if !selected {
        return Err(failure());
    }
    Ok("none".into())
}

fn parse_boot_bytes(bytes: &[u8]) -> Result<BootId, ProviderError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProviderError::InvalidState("kernel boot identity is not UTF-8".into()))?;
    let text = text
        .strip_suffix('\n')
        .ok_or_else(|| ProviderError::InvalidState("kernel boot identity is incomplete".into()))?;
    BootId::new(text).map_err(invalid_epoch)
}

fn validate_owner(owner: &str, uid: u32) -> Result<(), ProviderError> {
    if uid != 0 || zbus::names::UniqueName::try_from(owner).is_err() {
        return Err(ProviderError::InvalidState(
            "logind is not owned by an authenticated root service".into(),
        ));
    }
    Ok(())
}

fn validate_session_rows(rows: &[SessionRow]) -> Result<(), ProviderError> {
    if rows.len() > MAX_SESSIONS {
        return Err(ProviderError::InvalidState(
            "logind session enumeration exceeds the bounded resource ceiling".into(),
        ));
    }
    let mut identities = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (id, _uid, _account, _seat, path) in rows {
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !identities.insert(id)
            || !paths.insert(path.as_str())
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err(ProviderError::InvalidState(
                "logind session enumeration identity is ambiguous or malformed".into(),
            ));
        }
    }
    Ok(())
}

fn require_same_boot(expected: &BootId, observed: &BootId) -> Result<(), ProviderError> {
    if expected != observed {
        return Err(ProviderError::InvalidState(
            "session boot generation is no longer current".into(),
        ));
    }
    Ok(())
}

fn require_same_epoch(
    expected: &SessionEpoch,
    observed: &SessionEpoch,
) -> Result<(), ProviderError> {
    if expected != observed {
        return Err(ProviderError::InvalidState(
            "session epoch identity changed during observation".into(),
        ));
    }
    Ok(())
}

fn invalid_epoch(error: linura_core::SessionEpochError) -> ProviderError {
    ProviderError::InvalidState(error.to_string())
}
fn bus_error(_error: zbus::Error) -> ProviderError {
    ProviderError::Unavailable("native logind observation is unavailable or timed out".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone)]
    enum ProbeValue {
        Number(u64),
        Boot(BootId),
        Owner(String),
        Present(bool),
        Mode(String),
        Preparing(bool),
        OwnerChecked,
    }

    struct ScriptedTransitionProbe {
        steps: VecDeque<(&'static str, Result<ProbeValue, ProviderError>)>,
        visited: Vec<&'static str>,
    }

    impl ScriptedTransitionProbe {
        fn take(&mut self, operation: &'static str) -> Result<ProbeValue, ProviderError> {
            self.visited.push(operation);
            let (expected, result) = self
                .steps
                .pop_front()
                .unwrap_or_else(|| unreachable!("unexpected native probe"));
            assert_eq!(operation, expected, "native probe ordering changed");
            result
        }

        fn replace(
            &mut self,
            operation: &str,
            occurrence: usize,
            result: Result<ProbeValue, ProviderError>,
        ) {
            self.steps
                .iter_mut()
                .filter(|(name, _)| *name == operation)
                .nth(occurrence)
                .unwrap_or_else(|| unreachable!("native test step exists"))
                .1 = result;
        }
    }

    impl TransitionProbe for ScriptedTransitionProbe {
        fn now_unix_ms(&mut self) -> Result<u64, ProviderError> {
            match self.take("clock")? {
                ProbeValue::Number(value) => Ok(value),
                _ => unreachable!("clock fixture"),
            }
        }
        fn current_boot(&mut self) -> Result<BootId, ProviderError> {
            match self.take("boot")? {
                ProbeValue::Boot(value) => Ok(value),
                _ => unreachable!("boot fixture"),
            }
        }
        fn trusted_owner(&mut self) -> Result<String, ProviderError> {
            match self.take("owner")? {
                ProbeValue::Owner(value) => Ok(value),
                _ => unreachable!("owner fixture"),
            }
        }
        fn epoch_present(
            &mut self,
            owner: &str,
            expected: &SessionEpoch,
            current: &BootId,
        ) -> Result<bool, ProviderError> {
            assert_eq!(owner, ":1.17");
            assert_eq!(expected, &epoch(1000, 42));
            assert_eq!(current.as_str(), BOOT);
            match self.take("epoch")? {
                ProbeValue::Present(value) => Ok(value),
                _ => unreachable!("epoch fixture"),
            }
        }
        fn suspend_success_count(&mut self) -> Result<u64, ProviderError> {
            match self.take("counter")? {
                ProbeValue::Number(value) => Ok(value),
                _ => unreachable!("counter fixture"),
            }
        }
        fn suspend_test_mode(&mut self) -> Result<String, ProviderError> {
            match self.take("mode")? {
                ProbeValue::Mode(value) => Ok(value),
                _ => unreachable!("mode fixture"),
            }
        }
        fn preparing_for_sleep(&mut self, owner: &str) -> Result<bool, ProviderError> {
            assert_eq!(owner, ":1.17");
            match self.take("preparing")? {
                ProbeValue::Preparing(value) => Ok(value),
                _ => unreachable!("preparing fixture"),
            }
        }
        fn require_same_owner(&mut self, expected: &str) -> Result<(), ProviderError> {
            assert_eq!(expected, ":1.17");
            match self.take("owner-check")? {
                ProbeValue::OwnerChecked => Ok(()),
                _ => unreachable!("owner revalidation fixture"),
            }
        }
    }

    fn suspend_target(baseline: u64) -> SessionTransitionId {
        let lock = id(linura_core::SessionLockId::new(
            epoch(1000, 42),
            id(linura_core::SecurityOwnerInvocationId::new(
                "11223344-1234-4567-89ab-0123456789ab",
            )),
            7,
        ));
        id(SessionTransitionId::new(
            lock,
            SessionTransition::Suspend {
                successful_cycles_before: baseline,
            },
        ))
    }

    fn transition_probe(before: u64, after: u64, preparing: bool) -> ScriptedTransitionProbe {
        use ProbeValue as V;
        ScriptedTransitionProbe {
            steps: VecDeque::from([
                ("clock", Ok(V::Number(1_000))),
                ("boot", Ok(V::Boot(id(BootId::new(BOOT))))),
                ("owner", Ok(V::Owner(":1.17".into()))),
                ("clock", Ok(V::Number(1_001))),
                ("epoch", Ok(V::Present(true))),
                ("clock", Ok(V::Number(1_002))),
                ("counter", Ok(V::Number(before))),
                ("mode", Ok(V::Mode("none".into()))),
                ("clock", Ok(V::Number(1_003))),
                ("preparing", Ok(V::Preparing(preparing))),
                ("counter", Ok(V::Number(after))),
                ("mode", Ok(V::Mode("none".into()))),
                ("clock", Ok(V::Number(1_004))),
                ("epoch", Ok(V::Present(true))),
                ("boot", Ok(V::Boot(id(BootId::new(BOOT))))),
                ("owner-check", Ok(V::OwnerChecked)),
                ("clock", Ok(V::Number(1_005))),
            ]),
            visited: Vec::new(),
        }
    }

    #[test]
    fn exact_suspend_crossing_discards_all_facts_only_after_final_native_checks() {
        for baseline in [10, u64::MAX - 1] {
            for preparing in [false, true] {
                let mut probe = transition_probe(baseline, baseline + 1, preparing);
                assert!(id(sample_transition(&mut probe, &suspend_target(baseline))).is_none());
                assert!(probe.steps.is_empty());
                assert_eq!(
                    &probe.visited[probe.visited.len() - 4..],
                    &["epoch", "boot", "owner-check", "clock"]
                );
            }
        }
    }

    #[test]
    fn stable_suspend_samples_retain_original_freshness_and_all_native_facts() {
        for (cycles, preparing) in [(10, false), (10, true), (11, false), (12, false)] {
            let mut probe = transition_probe(cycles, cycles, preparing);
            let sample = id(sample_transition(&mut probe, &suspend_target(10)))
                .unwrap_or_else(|| unreachable!("complete stable native sample"));
            assert!(probe.steps.is_empty());
            assert_eq!(sample.observed_at_unix_ms, 1_000);
            assert_eq!(sample.attributes.len(), 5);
            assert_eq!(
                sample.attributes.get("successful_suspend_cycles"),
                Some(&ObservedValue::U64(cycles))
            );
            assert_eq!(
                sample.attributes.get("preparing_for_sleep"),
                Some(&ObservedValue::Bool(preparing))
            );
            assert_eq!(
                sample.attributes.get("suspend_test_mode"),
                Some(&ObservedValue::Text("none".into()))
            );
        }
    }

    #[test]
    fn unknown_counter_changes_and_overflow_never_become_known_pending() {
        for (baseline, before, after) in [
            (10, 10, 12),
            (10, 11, 12),
            (10, 11, 10),
            (10, 9, 10),
            (u64::MAX - 1, u64::MAX, 0),
        ] {
            let mut probe = transition_probe(before, after, false);
            assert!(matches!(
                sample_transition(&mut probe, &suspend_target(baseline)),
                Err(ProviderError::InvalidState(_))
            ));
            assert_eq!(probe.visited.last(), Some(&"mode"));
        }
    }

    #[test]
    fn changed_debug_mode_is_read_and_rejected_even_during_exact_counter_crossing() {
        for index in [0, 1] {
            let mut probe = transition_probe(10, 11, false);
            probe.replace("mode", index, Ok(ProbeValue::Mode("freezer".into())));
            assert!(matches!(
                sample_transition(&mut probe, &suspend_target(10)),
                Err(ProviderError::Unsupported(_))
            ));
            assert_eq!(
                probe.visited.iter().filter(|name| **name == "mode").count(),
                2
            );
        }
    }

    #[test]
    fn pending_native_sample_cannot_hide_epoch_boot_or_owner_replacement() {
        for (operation, occurrence, response) in [
            ("epoch", 0, Ok(ProbeValue::Present(false))),
            ("epoch", 1, Ok(ProbeValue::Present(false))),
            (
                "boot",
                1,
                Ok(ProbeValue::Boot(id(BootId::new(
                    "12345678-1234-4567-89ab-0123456789ab",
                )))),
            ),
            (
                "owner-check",
                0,
                Err(ProviderError::Unavailable("owner changed".into())),
            ),
        ] {
            let mut probe = transition_probe(10, 11, false);
            probe.replace(operation, occurrence, response);
            assert!(sample_transition(&mut probe, &suspend_target(10)).is_err());
        }
    }

    #[test]
    fn exact_native_crossing_cannot_extend_probe_deadline_or_recover_transport_errors() {
        for final_clock in [999, 3_000, u64::MAX] {
            let mut probe = transition_probe(10, 11, false);
            probe.replace("clock", 5, Ok(ProbeValue::Number(final_clock)));
            assert!(matches!(
                sample_transition(&mut probe, &suspend_target(10)),
                Err(ProviderError::Unavailable(_))
            ));
            assert!(probe.steps.is_empty());
        }
        for (operation, occurrence) in [
            ("owner", 0),
            ("epoch", 0),
            ("counter", 0),
            ("mode", 0),
            ("preparing", 0),
            ("counter", 1),
            ("mode", 1),
            ("epoch", 1),
            ("boot", 1),
            ("owner-check", 0),
            ("clock", 5),
        ] {
            let mut probe = transition_probe(10, 11, false);
            let failure = ProviderError::Unavailable("native fixture timeout".into());
            probe.replace(operation, occurrence, Err(failure.clone()));
            assert!(matches!(
                sample_transition(&mut probe, &suspend_target(10)),
                Err(error) if error == failure
            ));
            assert_eq!(probe.visited.last(), Some(&operation));
        }
        let mut malformed = transition_probe(10, 11, false);
        malformed.replace(
            "preparing",
            0,
            Err(ProviderError::InvalidState("malformed native bool".into())),
        );
        assert!(matches!(
            sample_transition(&mut malformed, &suspend_target(10)),
            Err(ProviderError::InvalidState(_))
        ));
    }

    #[test]
    fn suspend_counter_cannot_accept_awake_hints_aliases_or_overflow() {
        assert_eq!(id(decode_suspend_success(b"0\n")), 0);
        assert_eq!(id(decode_suspend_success(b"42\n")), 42);
        assert_eq!(
            id(decode_suspend_success(b"18446744073709551615\n")),
            u64::MAX
        );
        for bytes in [
            b"".as_slice(),
            b"42",
            b"042\n",
            b"+42\n",
            b"-1\n",
            b" 42\n",
            b"42\n0\n",
            b"true\n",
            b"awake\n",
            b"18446744073709551616\n",
            b"42\0\n",
        ] {
            assert!(decode_suspend_success(bytes).is_err());
        }
    }

    #[test]
    fn suspend_dry_run_modes_cannot_become_native_completion_evidence() {
        assert_eq!(
            id(decode_suspend_test_mode(
                b"[none] freezer devices platform processors core\n"
            )),
            "none"
        );
        assert_eq!(id(decode_suspend_test_mode(b"[none]\n")), "none");
        for bytes in [
            b"".as_slice(),
            b"[none]",
            b"none [freezer]\n",
            b"none [devices]\n",
            b"[none] [core]\n",
            b"[none] unknown\n",
            b"[none] [none]\n",
            b"[none] devices devices\n",
        ] {
            assert!(decode_suspend_test_mode(bytes).is_err());
        }
        // This ordinary file is neither native sysfs nor authority evidence.
        assert!(read_power_fact("/etc/os-release", 4096).is_err());
    }

    #[test]
    fn native_power_permissions_are_never_retargeted_from_service_root_or_recycled_session() {
        let expected = epoch(1000, 42);
        assert!(require_power_query_identity(&expected, 1000, &expected).is_ok());
        for (uid, queried) in [
            (0, expected.clone()),
            (999, expected.clone()),
            (1001, epoch(1001, 42)),
            (1000, epoch(1000, 43)),
            (
                1000,
                id(SessionEpoch::new(
                    id(BootId::new("12345678-1234-4567-89ab-0123456789ab")),
                    1000,
                    expected.session_id(),
                    42,
                )),
            ),
        ] {
            assert!(matches!(
                require_power_query_identity(&expected, uid, &queried),
                Err(ProviderError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn native_reply_limit_is_checked_before_decoding_user_controlled_arrays() {
        let message = |bytes: usize| {
            zbus::Message::method_call(MANAGER_PATH, "ListInhibitors")
                .and_then(|builder| builder.build(&vec![0_u8; bytes]))
                .unwrap_or_else(|error| unreachable!("{error}"))
        };
        let exact = message(MAX_NATIVE_REPLY_BODY_BYTES - 4);
        assert_eq!(exact.body().len(), MAX_NATIVE_REPLY_BODY_BYTES);
        assert!(require_reply_bound(&exact).is_ok());
        let oversized = message(MAX_NATIVE_REPLY_BODY_BYTES - 3);
        assert_eq!(oversized.body().len(), MAX_NATIVE_REPLY_BODY_BYTES + 1);
        assert!(matches!(
            require_reply_bound(&oversized),
            Err(ProviderError::InvalidState(_))
        ));
    }

    #[test]
    fn power_shared_session_analysis_cannot_ignore_reused_seats_closing_users_or_unknown_classes() {
        let expected = epoch(1000, 42);
        let mut other = id(SessionSnapshot::from_properties(
            &native_properties(),
            id(BootId::new(BOOT)),
        ));
        other.epoch = epoch(1000, 43);
        for class in [
            "user",
            "user-early",
            "user-incomplete",
            "user-light",
            "greeter",
            "lock-screen",
        ] {
            other.session_class = class.into();
            other.state = "closing".into();
            assert!(id(session_blocks_machine_power(&other, &expected)));
        }
        other.session_class = "manager".into();
        assert!(!id(session_blocks_machine_power(&other, &expected)));
        other.epoch = epoch(1001, 43);
        assert!(id(session_blocks_machine_power(&other, &expected)));
        other.session_class = "future-class".into();
        assert!(session_blocks_machine_power(&other, &expected).is_err());
    }

    #[test]
    fn power_availability_unknown_or_normalized_values_fail_closed() {
        for value in ["yes", "no", "challenge", "na"] {
            assert!(validate_power_availability(value).is_ok());
        }
        for value in ["", "unknown", "YES", "yes ", "authorized", "true"] {
            assert!(validate_power_availability(value).is_err());
        }
    }

    #[test]
    fn inhibitor_counts_preserve_block_weak_and_never_expose_descriptions_or_handles() {
        let rows = vec![
            (
                "sleep:shutdown".into(),
                "private application".into(),
                "private reason".into(),
                "block-weak".into(),
                1000,
                123,
            ),
            (
                "sleep".into(),
                "another application".into(),
                "another reason".into(),
                "delay".into(),
                1001,
                456,
            ),
        ];
        let facts = id(inhibitor_counts(&rows));
        assert_eq!(facts.get("sleep_block_count"), Some(&ObservedValue::U64(1)));
        assert_eq!(
            facts.get("shutdown_block_count"),
            Some(&ObservedValue::U64(1))
        );
        assert_eq!(facts.get("sleep_delay_count"), Some(&ObservedValue::U64(1)));
        assert_eq!(
            facts.get("shutdown_delay_count"),
            Some(&ObservedValue::U64(0))
        );
        assert_eq!(facts.len(), 4);
        let rendered = format!("{facts:?}");
        for forbidden in [
            "private",
            "application",
            "reason",
            "123",
            "456",
            "1000",
            "1001",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn unknown_duplicate_or_unbounded_native_inhibitors_are_not_silently_ignored() {
        let row = (
            "sleep".into(),
            "app".into(),
            "reason".into(),
            "block".into(),
            1000,
            123,
        );
        assert!(inhibitor_counts(&vec![row.clone(); MAX_INHIBITORS + 1]).is_err());
        for what in ["", "sleep:sleep", "sleep:new-kind", "sleep:", " sleep"] {
            let mut changed = row.clone();
            changed.0 = what.into();
            assert!(inhibitor_counts(&[changed]).is_err());
        }
        for mode in ["", "ignore", "BLOCK", "allow"] {
            let mut changed = row.clone();
            changed.3 = mode.into();
            assert!(inhibitor_counts(&[changed]).is_err());
        }
        let mut changed = row.clone();
        changed.1 = "a".repeat(513);
        assert!(inhibitor_counts(&[changed]).is_err());
        let mut changed = row;
        changed.5 = 0;
        assert!(inhibitor_counts(&[changed]).is_err());
    }
    const BOOT: &str = "abcd1234-1234-4567-89ab-0123456789ab";
    fn id<T, E: Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn epoch(uid: u32, generation: u64) -> SessionEpoch {
        id(SessionEpoch::new(
            id(BootId::new(BOOT)),
            uid,
            "2",
            generation,
        ))
    }

    fn value(value: impl Into<zbus::zvariant::Value<'static>>) -> OwnedValue {
        id(OwnedValue::try_from(value.into()))
    }

    fn native_properties() -> HashMap<String, OwnedValue> {
        HashMap::from([
            ("Id".into(), value("2")),
            (
                "User".into(),
                value((
                    1000_u32,
                    id(OwnedObjectPath::try_from(
                        "/org/freedesktop/login1/user/_1000",
                    )),
                )),
            ),
            ("TimestampMonotonic".into(), value(42_u64)),
            (
                "Seat".into(),
                value((
                    "seat0",
                    id(OwnedObjectPath::try_from(
                        "/org/freedesktop/login1/seat/seat0",
                    )),
                )),
            ),
            ("Type".into(), value("wayland")),
            ("Class".into(), value("user")),
            ("State".into(), value("active")),
            ("Active".into(), value(true)),
            ("Remote".into(), value(false)),
            ("LockedHint".into(), value(false)),
            ("Leader".into(), value(99_u32)),
        ])
    }

    #[test]
    fn native_snapshot_decodes_typed_identity_without_transport_leakage() {
        let snapshot = id(SessionSnapshot::from_properties(
            &native_properties(),
            id(BootId::new(BOOT)),
        ));
        assert_eq!(snapshot.epoch, epoch(1000, 42));
        let attributes = snapshot.attributes();
        assert_eq!(
            attributes.get("leader_present"),
            Some(&ObservedValue::Bool(true))
        );
        assert!(!attributes.contains_key("leader_pid"));
        assert!(!attributes.contains_key("user_path"));
    }

    #[test]
    fn every_required_property_is_mandatory_and_wrong_native_types_fail_closed() {
        for key in native_properties().keys() {
            let mut missing = native_properties();
            missing.remove(key);
            assert!(
                SessionSnapshot::from_properties(&missing, id(BootId::new(BOOT))).is_err(),
                "missing {key}"
            );
            let mut wrong_type = native_properties();
            wrong_type.insert(key.clone(), value(vec!["wrong", "type"]));
            assert!(
                SessionSnapshot::from_properties(&wrong_type, id(BootId::new(BOOT))).is_err(),
                "wrong type {key}"
            );
        }
    }

    #[test]
    fn unknown_or_unbounded_session_state_is_not_normalized_into_support() {
        for (key, replacement) in [
            ("State", value("unknown")),
            ("Type", value("")),
            ("Class", value("")),
            ("Seat", value("private\nvalue")),
            ("Class", value("x".repeat(65))),
            ("TimestampMonotonic", value(0_u64)),
            ("Id", value("../2")),
        ] {
            let mut properties = native_properties();
            properties.insert(key.into(), replacement);
            assert!(
                SessionSnapshot::from_properties(&properties, id(BootId::new(BOOT))).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn owner_identity_is_authenticated_not_a_well_known_name() {
        assert!(validate_owner(":1.42", 0).is_ok());
        assert!(validate_owner(":1.42", 1000).is_err());
        assert!(validate_owner(SERVICE, 0).is_err());
        assert!(validate_owner("", 0).is_err());
    }

    #[test]
    fn generation_checks_fail_closed_on_reuse_cross_user_and_reboot() {
        let original = epoch(1000, 42);
        assert!(require_same_epoch(&original, &epoch(1000, 42)).is_ok());
        assert!(require_same_epoch(&original, &epoch(1000, 43)).is_err());
        assert!(require_same_epoch(&original, &epoch(1001, 42)).is_err());
        let other_boot = id(BootId::new("abcd1234-1234-4567-89ab-0123456789ac"));
        assert!(require_same_boot(original.boot(), &other_boot).is_err());
    }

    #[test]
    fn kernel_identity_is_bounded_and_not_trimmed_into_validity() {
        assert_eq!(
            id(parse_boot_bytes(format!("{BOOT}\n").as_bytes())).as_str(),
            BOOT
        );
        for invalid in [
            BOOT.to_owned(),
            format!(" {BOOT}\n"),
            format!("{BOOT}\n\n"),
            format!("{BOOT}\r\n"),
            "x".repeat(38),
        ] {
            assert!(parse_boot_bytes(invalid.as_bytes()).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn lock_hint_never_becomes_security_evidence_or_leaks_native_handles() {
        let snapshot = SessionSnapshot {
            epoch: epoch(1000, 42),
            session_type: "wayland".into(),
            session_class: "user".into(),
            state: "active".into(),
            seat: "seat0".into(),
            active: true,
            remote: false,
            locked_hint: true,
            leader: 99,
        };
        let attributes = snapshot.attributes();
        assert_eq!(
            attributes.get("locked_hint"),
            Some(&ObservedValue::Bool(true))
        );
        for prohibited in [
            "secure",
            "locked",
            "screen_coverage",
            "object_path",
            "user_path",
            "account_name",
            "leader_pid",
            "authenticated",
        ] {
            assert!(!attributes.contains_key(prohibited), "{prohibited}");
        }
    }

    #[test]
    fn missing_native_properties_cannot_be_observed_as_defaults() {
        assert!(SessionSnapshot::from_properties(&HashMap::new(), id(BootId::new(BOOT))).is_err());
    }

    #[test]
    fn enumeration_is_bounded_and_rejects_identity_and_handle_aliases() {
        let row = (
            "2".into(),
            1000,
            "omitted-account".into(),
            "seat0".into(),
            id(OwnedObjectPath::try_from(
                "/org/freedesktop/login1/session/_32",
            )),
        );
        assert!(validate_session_rows(std::slice::from_ref(&row)).is_ok());
        assert!(validate_session_rows(&vec![row.clone(); MAX_SESSIONS + 1]).is_err());
        assert!(validate_session_rows(&[row.clone(), row.clone()]).is_err());
        let mut alias = row.clone();
        alias.0 = "3".into();
        assert!(validate_session_rows(&[row.clone(), alias]).is_err());
        let mut alias = row.clone();
        alias.4 = id(OwnedObjectPath::try_from(
            "/org/freedesktop/login1/session/_33",
        ));
        assert!(validate_session_rows(&[row.clone(), alias]).is_err());
        let mut invalid = row;
        invalid.4 = id(OwnedObjectPath::try_from("/org/freedesktop/login1"));
        assert!(validate_session_rows(&[invalid]).is_err());
    }
}
