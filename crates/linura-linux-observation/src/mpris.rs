//! Read-only, current-user MPRIS observation. Player metadata is data, never authority.
//! No player method, URI, album art or external command is dispatched by this adapter.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use linura_core::{Capability, CapabilityId, ProviderId, ResourceId};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use rustix::process::geteuid;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::{capability, next_sequence, now_unix_ms, provider_id};

pub const MPRIS_PROVIDER: &str = "mpris";
pub const MPRIS_PLAYER_CAPABILITY: &str = "mpris.player.observe";
const RESOURCE_PREFIX: &str = "mpris:player:";
const SERVICE_PREFIX: &str = "org.mpris.MediaPlayer2.";
const BUS_SERVICE: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_INTERFACE: &str = "org.freedesktop.DBus";
const PLAYER_PATH: &str = "/org/mpris/MediaPlayer2";
const PLAYER_INTERFACE: &str = "org.mpris.MediaPlayer2.Player";
const ROOT_INTERFACE: &str = "org.mpris.MediaPlayer2";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const MAX_BUS_NAMES: usize = 1024;
const MAX_PLAYERS: usize = 32;
const MAX_SERVICE_NAME: usize = 170;
const MAX_UNIQUE_OWNER: usize = 64;
const MAX_LABEL_BYTES: usize = 512;
const PLAYER_VALID_FOR_MS: u64 = 1_000;

pub struct MprisObserver {
    connection: Connection,
    bus_id: String,
    uid: u32,
    sequence: AtomicU64,
}

impl Debug for MprisObserver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MprisObserver").finish_non_exhaustive()
    }
}

impl MprisObserver {
    pub fn connect() -> Result<Self, ProviderError> {
        let connection = zbus::blocking::connection::Builder::session()
            .map_err(|_| {
                ProviderError::Unavailable("current session D-Bus is unavailable for MPRIS".into())
            })?
            .method_timeout(Duration::from_millis(750))
            .build()
            .map_err(|_| {
                ProviderError::Unavailable("current session D-Bus is unavailable for MPRIS".into())
            })?;
        let bus_id = bus_id(&connection)?;
        if bus_id.is_empty() || bus_id.len() > 128 || !bus_id.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ProviderError::InvalidState(
                "invalid session-bus identity".into(),
            ));
        }
        let uid = geteuid().as_raw();
        let own_name = connection.unique_name().ok_or_else(|| {
            ProviderError::Unavailable("session-bus connection has no unique identity".into())
        })?;
        let own_uid = connection_uid(&connection, own_name.as_str())?;
        if own_uid != uid {
            return Err(ProviderError::Unavailable(
                "session-bus principal does not match process identity".into(),
            ));
        }
        Ok(Self {
            connection,
            bus_id,
            uid,
            sequence: AtomicU64::new(0),
        })
    }

    fn require_bus(&self) -> Result<(), ProviderError> {
        if bus_id(&self.connection)? != self.bus_id {
            return Err(ProviderError::Unavailable(
                "MPRIS session-bus identity changed".into(),
            ));
        }
        let own = self.connection.unique_name().ok_or_else(|| {
            ProviderError::Unavailable("session-bus connection lost its identity".into())
        })?;
        if connection_uid(&self.connection, own.as_str())? != self.uid {
            return Err(ProviderError::Unavailable(
                "session principal changed".into(),
            ));
        }
        Ok(())
    }

    fn player_names(&self) -> Result<Vec<String>, ProviderError> {
        self.require_bus()?;
        let names: Vec<String> = bus_proxy(&self.connection)?
            .call("ListNames", &())
            .map_err(|_| ProviderError::Unavailable("MPRIS service enumeration failed".into()))?;
        if names.len() > MAX_BUS_NAMES {
            return Err(ProviderError::InvalidState(
                "session-bus name budget exceeded".into(),
            ));
        }
        let mut players: Vec<String> = names
            .into_iter()
            .filter(|name| name.starts_with(SERVICE_PREFIX))
            .collect();
        if players.len() > MAX_PLAYERS {
            return Err(ProviderError::InvalidState(
                "MPRIS player budget exceeded".into(),
            ));
        }
        players.sort();
        if players.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProviderError::InvalidState(
                "duplicate MPRIS service name".into(),
            ));
        }
        for name in &players {
            validate_service(name)?;
        }
        self.require_bus()?;
        Ok(players)
    }

    fn owner(&self, service: &str) -> Result<String, ProviderError> {
        let owner: String = bus_proxy(&self.connection)?
            .call("GetNameOwner", &(service,))
            .map_err(|_| ProviderError::Unavailable("MPRIS player has no current owner".into()))?;
        validate_owner(&owner)?;
        if connection_uid(&self.connection, &owner)? != self.uid {
            return Err(ProviderError::Unavailable(
                "MPRIS player is not owned by the current user".into(),
            ));
        }
        Ok(owner)
    }

    fn player_properties(
        &self,
        owner: &str,
        interface: &str,
    ) -> Result<HashMap<String, OwnedValue>, ProviderError> {
        // A unique-name destination cannot be retargeted when a well-known name is rebound.
        let proxy = Proxy::new(&self.connection, owner, PLAYER_PATH, PROPERTIES)
            .map_err(|_| ProviderError::Unavailable("MPRIS player is unavailable".into()))?;
        proxy
            .call("GetAll", &(interface,))
            .map_err(|_| ProviderError::Unavailable("MPRIS property read failed".into()))
    }
}

impl Observer for MprisObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(MPRIS_PROVIDER)
    }

    fn requires_live_health_preflight(&self) -> bool {
        false // Each requested read verifies its bus and unique owner again.
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        vec![capability(
            MPRIS_PLAYER_CAPABILITY,
            MPRIS_PROVIDER,
            health.availability,
            health.reason,
        )]
    }

    fn health(&self) -> ProviderHealth {
        match self.player_names() {
            Ok(_) => ProviderHealth {
                provider: provider_id(MPRIS_PROVIDER),
                availability: ProviderAvailability::Available,
                reason: None,
            },
            Err(error) => ProviderHealth {
                provider: provider_id(MPRIS_PROVIDER),
                availability: ProviderAvailability::Unavailable,
                reason: Some(error.to_string()),
            },
        }
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        let mut resources = Vec::new();
        for name in self.player_names()? {
            let owner = self.owner(&name)?;
            resources.push(resource_id(&name, &owner)?);
        }
        self.require_bus()?;
        resources.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(resources)
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        requested: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if requested.as_str() != MPRIS_PLAYER_CAPABILITY {
            return Err(ProviderError::Unsupported(
                "unsupported MPRIS observation".into(),
            ));
        }
        let (name, expected_owner) = parse_resource(resource)?;
        self.require_bus()?;
        let actual_owner = self.owner(name)?;
        if actual_owner != expected_owner {
            return Err(ProviderError::Unavailable(
                "MPRIS player owner changed".into(),
            ));
        }
        let root = self.player_properties(&actual_owner, ROOT_INTERFACE)?;
        let player = self.player_properties(&actual_owner, PLAYER_INTERFACE)?;

        let status = required_text(&player, "PlaybackStatus", 16)?;
        if !matches!(status.as_str(), "Playing" | "Paused" | "Stopped") {
            return Err(ProviderError::InvalidState(
                "invalid MPRIS playback status".into(),
            ));
        }
        let identity = safe_label(&required_text(&root, "Identity", MAX_LABEL_BYTES)?)?;
        let can_control = required_bool(&player, "CanControl")?;
        let metadata: HashMap<String, OwnedValue> = match player.get("Metadata") {
            Some(value) => HashMap::<String, OwnedValue>::try_from(
                value
                    .try_clone()
                    .map_err(|_| invalid("MPRIS metadata is invalid"))?,
            )
            .map_err(|_| invalid("MPRIS metadata has the wrong type"))?,
            None => return Err(invalid("MPRIS metadata is missing")),
        };
        if metadata.len() > 64 {
            return Err(invalid("MPRIS metadata exceeds field budget"));
        }

        let mut attributes = BTreeMap::from([
            ("bus_id".into(), ObservedValue::Text(self.bus_id.clone())),
            ("service_name".into(), ObservedValue::Text(name.into())),
            (
                "unique_owner".into(),
                ObservedValue::Text(actual_owner.clone()),
            ),
            ("owner_uid".into(), ObservedValue::U64(u64::from(self.uid))),
            ("identity_escaped".into(), ObservedValue::Text(identity)),
            ("playback_status".into(), ObservedValue::Text(status)),
            ("can_control".into(), ObservedValue::Bool(can_control)),
        ]);
        for property in [
            "CanPlay",
            "CanPause",
            "CanGoNext",
            "CanGoPrevious",
            "CanSeek",
        ] {
            attributes.insert(
                camel_to_snake(property).into(),
                ObservedValue::Bool(can_control && required_bool(&player, property)?),
            );
        }
        if let Some(title) = optional_text(&metadata, "xesam:title", MAX_LABEL_BYTES)? {
            attributes.insert(
                "title_escaped".into(),
                ObservedValue::Text(safe_label(&title)?),
            );
        }
        if let Some(value) = metadata.get("mpris:trackid") {
            let path = OwnedObjectPath::try_from(
                value
                    .try_clone()
                    .map_err(|_| invalid("invalid MPRIS track identity"))?,
            )
            .map_err(|_| invalid("invalid MPRIS track identity"))?;
            if path.as_str().len() > 256 {
                return Err(invalid("MPRIS track identity exceeds budget"));
            }
            attributes.insert("track_id".into(), ObservedValue::Text(path.to_string()));
        }
        if let Some(value) = metadata.get("mpris:length") {
            let length = i64::try_from(
                value
                    .try_clone()
                    .map_err(|_| invalid("invalid MPRIS duration"))?,
            )
            .map_err(|_| invalid("invalid MPRIS duration"))?;
            if !(0..=86_400_000_000).contains(&length) {
                return Err(invalid("MPRIS duration out of bounds"));
            }
            attributes.insert("length_us".into(), ObservedValue::I64(length));
        }

        // Both properties interfaces are non-atomic reads. Preserve exact bus/owner
        // identity, but do NOT promote this read to a playback/seek authorization.
        if self.owner(name)? != actual_owner {
            return Err(ProviderError::Unavailable(
                "MPRIS player owner changed".into(),
            ));
        }
        self.require_bus()?;
        Ok(ObservationEnvelope {
            provider: provider_id(MPRIS_PROVIDER),
            resource: resource.clone(),
            capability: requested.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: PLAYER_VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes,
        })
    }
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::InvalidState(message.into())
}

fn bus_proxy(connection: &Connection) -> Result<Proxy<'_>, ProviderError> {
    Proxy::new(connection, BUS_SERVICE, BUS_PATH, BUS_INTERFACE)
        .map_err(|_| ProviderError::Unavailable("MPRIS session bus is unavailable".into()))
}

fn bus_id(connection: &Connection) -> Result<String, ProviderError> {
    bus_proxy(connection)?
        .call("GetId", &())
        .map_err(|_| ProviderError::Unavailable("cannot obtain session-bus identity".into()))
}

fn connection_uid(connection: &Connection, name: &str) -> Result<u32, ProviderError> {
    bus_proxy(connection)?
        .call("GetConnectionUnixUser", &(name,))
        .map_err(|_| ProviderError::Unavailable("cannot authenticate MPRIS bus owner".into()))
}

fn validate_service(name: &str) -> Result<(), ProviderError> {
    if !name.starts_with(SERVICE_PREFIX)
        || name.len() > MAX_SERVICE_NAME
        || name.len() <= SERVICE_PREFIX.len()
        || name.split('.').any(|part| part.is_empty())
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err(invalid("invalid MPRIS well-known name"));
    }
    Ok(())
}

fn validate_owner(owner: &str) -> Result<(), ProviderError> {
    if owner.len() < 4
        || owner.len() > MAX_UNIQUE_OWNER
        || !owner.starts_with(':')
        || owner[1..]
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()))
        || !owner[1..].contains('.')
    {
        return Err(invalid("invalid MPRIS unique owner"));
    }
    Ok(())
}

fn resource_id(name: &str, owner: &str) -> Result<ResourceId, ProviderError> {
    validate_service(name)?;
    validate_owner(owner)?;
    ResourceId::new(format!("{RESOURCE_PREFIX}{name}@{owner}"))
        .map_err(|_| invalid("MPRIS resource exceeds identity bound"))
}

fn parse_resource(resource: &ResourceId) -> Result<(&str, &str), ProviderError> {
    let raw = resource
        .as_str()
        .strip_prefix(RESOURCE_PREFIX)
        .ok_or_else(|| ProviderError::Unsupported("not an MPRIS player resource".into()))?;
    let (name, owner) = raw
        .split_once('@')
        .ok_or_else(|| invalid("MPRIS player resource has no owner"))?;
    validate_service(name)?;
    validate_owner(owner)?;
    Ok((name, owner))
}

fn required_bool(values: &HashMap<String, OwnedValue>, key: &str) -> Result<bool, ProviderError> {
    let value = values
        .get(key)
        .ok_or_else(|| invalid("missing required MPRIS property"))?;
    bool::try_from(
        value
            .try_clone()
            .map_err(|_| invalid("invalid MPRIS property"))?,
    )
    .map_err(|_| invalid("invalid MPRIS property type"))
}

fn required_text(
    values: &HashMap<String, OwnedValue>,
    key: &str,
    bound: usize,
) -> Result<String, ProviderError> {
    optional_text(values, key, bound)?
        .ok_or_else(|| invalid("missing required MPRIS text property"))
}

fn optional_text(
    values: &HashMap<String, OwnedValue>,
    key: &str,
    bound: usize,
) -> Result<Option<String>, ProviderError> {
    let Some(value) = values.get(key) else {
        return Ok(None);
    };
    let text = String::try_from(
        value
            .try_clone()
            .map_err(|_| invalid("invalid MPRIS text"))?,
    )
    .map_err(|_| invalid("invalid MPRIS text type"))?;
    if text.len() > bound || text.chars().any(char::is_control) {
        return Err(invalid("MPRIS text is unsafe or exceeds budget"));
    }
    Ok(Some(text))
}

fn safe_label(input: &str) -> Result<String, ProviderError> {
    if input.len() > MAX_LABEL_BYTES || input.chars().any(char::is_control) {
        return Err(invalid(
            "MPRIS presentation label is unsafe or exceeds budget",
        ));
    }
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
        if escaped.len() > MAX_LABEL_BYTES * 6 {
            return Err(invalid("escaped MPRIS label exceeds budget"));
        }
    }
    Ok(escaped)
}

fn camel_to_snake(value: &str) -> &'static str {
    match value {
        "CanPlay" => "can_play",
        "CanPause" => "can_pause",
        "CanGoNext" => "can_go_next",
        "CanGoPrevious" => "can_go_previous",
        "CanSeek" => "can_seek",
        _ => unreachable!("static MPRIS capability field"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn player_resources_pin_unique_owner_and_reject_retargeting() {
        let id = resource_id("org.mpris.MediaPlayer2.Example", ":1.42").unwrap();
        assert_eq!(
            parse_resource(&id).unwrap(),
            ("org.mpris.MediaPlayer2.Example", ":1.42")
        );
        assert_ne!(
            id,
            resource_id("org.mpris.MediaPlayer2.Example", ":1.43").unwrap()
        );
        for candidate in [
            "mpris:player:org.mpris.MediaPlayer2.Example",
            "mpris:player:org.mpris.MediaPlayer2.Example@:0",
            "mpris:player:org.mpris.MediaPlayer2.Example@:1.2@more",
            "mpris:player:org.mpris.MediaPlayer2.Example@:1.bad",
            "mpris:player:org.mpris.MediaPlayer2.Example@:1.2/evil",
            "mpris:player:org.mpris.MediaPlayer2.@:1.2",
            "mpris:player:org.mpris.MediaPlayer2..Bad@:1.2",
            "mpris:player:org.mpris.MediaPlayer2.Example@:1..2",
        ] {
            let value = ResourceId::new(candidate).unwrap();
            assert!(parse_resource(&value).is_err(), "{candidate}");
        }
    }

    #[test]
    fn untrusted_labels_are_bounded_and_escaped() {
        assert_eq!(
            safe_label("<bad & \"title\">").unwrap(),
            "&lt;bad &amp; &quot;title&quot;&gt;"
        );
        for value in ["hello\nworld", "a\tb"] {
            assert!(safe_label(value).is_err());
        }
        assert!(safe_label(&"x".repeat(MAX_LABEL_BYTES + 1)).is_err());
    }

    #[test]
    fn only_supported_current_player_properties_are_exposed() {
        assert_eq!(camel_to_snake("CanGoPrevious"), "can_go_previous");
        assert!(validate_service("org.mpris.MediaPlayer2.MyPlayer").is_ok());
        assert!(validate_service("org.mpris.MediaPlayer2.Evil@injection").is_err());
        assert!(validate_owner(":1.77").is_ok());
        assert!(validate_owner(":1.77anything").is_err());
    }
}
