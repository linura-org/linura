//! Bounded read-only projection of the current user's PipeWire graph.
//!
//! The fixed native pw-dump JSON snapshot is input DATA, not an executable
//! request, policy decision, atomic graph transaction or capture privacy proof.
//! This provider never dispatches a PipeWire mutation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::thread;
use std::time::{Duration, Instant};

use linura_core::{Capability, CapabilityId, ProviderId, ResourceId};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use rustix::process::geteuid;
use serde_json::Value;

use crate::{capability, next_sequence, now_unix_ms, provider_id, wireplumber_runtime_dir};

pub const AUDIO_GRAPH_PROVIDER: &str = "pipewire-graph";
pub const AUDIO_GRAPH_CAPABILITY: &str = "audio.graph.object.observe";
const RESOURCE_PREFIX: &str = "audio:graph:";
const EXECUTABLE: &str = "/usr/bin/pw-dump";
const DEADLINE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(10);
const MAX_JSON: u64 = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;
const MAX_AUDIO_NODES: usize = 256;
const MAX_GRAPH_OBJECTS: usize = 2048;
const MAX_LABEL: usize = 256;
const VALID_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Node,
    Device,
    Port,
    Link,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Device => "device",
            Self::Port => "port",
            Self::Link => "link",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AudioObject {
    kind: Kind,
    id: u32,
    serial: u64,
    name: String,
    media_class: Option<&'static str>,
    parent_node: Option<u32>,
    direction: Option<&'static str>,
    output_node: Option<u32>,
    input_node: Option<u32>,
    output_port: Option<u32>,
    input_port: Option<u32>,
}

impl AudioObject {
    fn resource(&self) -> Result<ResourceId, ProviderError> {
        ResourceId::new(format!(
            "{RESOURCE_PREFIX}{}:{}:{}",
            self.kind.as_str(),
            self.id,
            self.serial
        ))
        .map_err(|_| invalid("audio graph resource identity exceeds bound"))
    }

    fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut values = BTreeMap::from([
            ("id".into(), ObservedValue::U64(u64::from(self.id))),
            (
                "observer_uid".into(),
                ObservedValue::U64(u64::from(geteuid().as_raw())),
            ),
            ("object_serial".into(), ObservedValue::U64(self.serial)),
            (
                "kind".into(),
                ObservedValue::Text(self.kind.as_str().into()),
            ),
            (
                "name_escaped".into(),
                ObservedValue::Text(escape(&self.name)),
            ),
            (
                "capture_privacy_verified".into(),
                ObservedValue::Bool(false),
            ),
            ("snapshot_atomic".into(), ObservedValue::Bool(false)),
        ]);
        if let Some(class) = self.media_class {
            values.insert("media_class".into(), ObservedValue::Text(class.into()));
        }
        if let Some(direction) = self.direction {
            values.insert("direction".into(), ObservedValue::Text(direction.into()));
        }
        for (key, id) in [
            ("parent_node_id", self.parent_node),
            ("output_node_id", self.output_node),
            ("input_node_id", self.input_node),
            ("output_port_id", self.output_port),
            ("input_port_id", self.input_port),
        ] {
            if let Some(id) = id {
                values.insert(key.into(), ObservedValue::U64(u64::from(id)));
            }
        }
        values
    }
}

#[derive(Debug, Default)]
pub struct PipeWireGraphObserver {
    sequence: AtomicU64,
}

impl PipeWireGraphObserver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> Result<Vec<AudioObject>, ProviderError> {
        let text = dump_current_session()?;
        parse_snapshot(&text)
    }
}

impl Observer for PipeWireGraphObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(AUDIO_GRAPH_PROVIDER)
    }

    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        capability.as_str() == AUDIO_GRAPH_CAPABILITY
    }

    fn requires_live_health_preflight(&self) -> bool {
        false
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        vec![capability(
            AUDIO_GRAPH_CAPABILITY,
            AUDIO_GRAPH_PROVIDER,
            health.availability,
            health.reason,
        )]
    }

    fn health(&self) -> ProviderHealth {
        match self.snapshot() {
            Ok(_) => ProviderHealth {
                provider: provider_id(AUDIO_GRAPH_PROVIDER),
                availability: ProviderAvailability::Available,
                reason: None,
            },
            Err(error) => ProviderHealth {
                provider: provider_id(AUDIO_GRAPH_PROVIDER),
                availability: ProviderAvailability::Unavailable,
                reason: Some(error.to_string()),
            },
        }
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        let mut resources = self
            .snapshot()?
            .iter()
            .map(AudioObject::resource)
            .collect::<Result<Vec<_>, _>>()?;
        resources.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(resources)
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        requested: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if requested.as_str() != AUDIO_GRAPH_CAPABILITY {
            return Err(ProviderError::Unsupported(
                "unsupported PipeWire graph observation".into(),
            ));
        }
        parse_resource(resource)?;
        // Enumeration and the authoritative read must each be reobserved.
        // Exact ID + serial prevents accidental reuse across graph generations.
        let object = self
            .snapshot()?
            .into_iter()
            .find(|object| object.resource().as_ref() == Ok(resource))
            .ok_or_else(|| {
                ProviderError::Unavailable("PipeWire graph object changed or disappeared".into())
            })?;
        Ok(ObservationEnvelope {
            provider: provider_id(AUDIO_GRAPH_PROVIDER),
            resource: resource.clone(),
            capability: requested.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: VALID_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: object.attributes(),
        })
    }
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::InvalidState(message.into())
}

fn parse_resource(resource: &ResourceId) -> Result<(), ProviderError> {
    let parts: Vec<&str> = resource.as_str().split(':').collect();
    if parts.len() != 5 || parts[0] != "audio" || parts[1] != "graph" {
        return Err(invalid("invalid audio graph resource shape"));
    }
    if !matches!(parts[2], "node" | "device" | "port" | "link") {
        return Err(invalid("invalid audio graph resource kind"));
    }
    canonical_u32(parts[3])?;
    canonical_u64(parts[4])?;
    Ok(())
}

fn canonical_u64(text: &str) -> Result<u64, ProviderError> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(invalid("noncanonical audio graph integer"));
    }
    text.parse::<u64>()
        .map_err(|_| invalid("audio graph integer exceeds u64"))
}

fn canonical_u32(text: &str) -> Result<u32, ProviderError> {
    let number = canonical_u64(text)?;
    let id = u32::try_from(number).map_err(|_| invalid("audio graph id exceeds u32"))?;
    if id == u32::MAX {
        return Err(invalid("audio graph id is invalid"));
    }
    Ok(id)
}

fn property_u32(value: &Value, key: &str) -> Result<u32, ProviderError> {
    let raw = value
        .get(key)
        .ok_or_else(|| invalid("missing audio graph identity reference"))?;
    if let Some(text) = raw.as_str() {
        return canonical_u32(text);
    }
    let n = raw
        .as_u64()
        .ok_or_else(|| invalid("invalid audio graph identity reference"))?;
    u32::try_from(n)
        .ok()
        .filter(|v| *v != u32::MAX)
        .ok_or_else(|| invalid("audio graph identity reference out of range"))
}

fn serial(props: &Value) -> Result<u64, ProviderError> {
    let raw = props
        .get("object.serial")
        .ok_or_else(|| invalid("missing PipeWire object serial"))?;
    if let Some(s) = raw.as_str() {
        return canonical_u64(s);
    }
    raw.as_u64()
        .ok_or_else(|| invalid("invalid PipeWire object serial"))
}

fn label(raw: &str) -> Result<String, ProviderError> {
    if raw.is_empty() || raw.len() > MAX_LABEL || raw.chars().any(char::is_control) {
        return Err(invalid("invalid or excessive PipeWire label"));
    }
    Ok(raw.into())
}

fn escape(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(c),
        }
    }
    output
}

fn props(row: &Value) -> Result<&Value, ProviderError> {
    let props = row
        .get("info")
        .and_then(|v| v.get("props"))
        .ok_or_else(|| invalid("missing PipeWire object properties"))?;
    if !props.is_object() {
        return Err(invalid("invalid PipeWire properties type"));
    }
    Ok(props)
}

fn item_id(row: &Value) -> Result<u32, ProviderError> {
    let raw = row
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("PipeWire object missing id"))?;
    u32::try_from(raw)
        .ok()
        .filter(|v| *v != u32::MAX)
        .ok_or_else(|| invalid("PipeWire id out of range"))
}

fn parse_snapshot(raw: &str) -> Result<Vec<AudioObject>, ProviderError> {
    if raw.len() > MAX_JSON as usize {
        return Err(invalid("PipeWire snapshot exceeds byte budget"));
    }
    let value: Value =
        serde_json::from_str(raw).map_err(|_| invalid("PipeWire snapshot is not valid JSON"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("PipeWire snapshot must be an array"))?;
    if rows.len() > MAX_ITEMS {
        return Err(invalid("PipeWire snapshot exceeds object budget"));
    }

    let mut global_ids = BTreeSet::new();
    let mut global_serials = BTreeSet::new();
    // Select audio node IDs regardless of native JSON record order.
    let audio_node_ids: BTreeSet<u32> = rows
        .iter()
        .filter(|row| row.get("type").and_then(Value::as_str) == Some("PipeWire:Interface:Node"))
        .filter(|row| {
            row.get("info")
                .and_then(|info| info.get("props"))
                .and_then(|props| props.get("media.class"))
                .and_then(Value::as_str)
                .is_some_and(|class| {
                    matches!(
                        class,
                        "Audio/Sink"
                            | "Audio/Source"
                            | "Stream/Output/Audio"
                            | "Stream/Input/Audio"
                    )
                })
        })
        .filter_map(|row| item_id(row).ok())
        .collect();
    let mut nodes = BTreeMap::new();
    let mut attached_devices = BTreeSet::new();
    let mut devices = Vec::new();
    let mut ports = Vec::new();
    let mut links = Vec::new();

    for row in rows {
        let id = item_id(row)?;
        if !global_ids.insert(id) {
            return Err(invalid("duplicate PipeWire object id"));
        }
        let object_type = row
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing PipeWire interface type"))?;
        if !matches!(
            object_type,
            "PipeWire:Interface:Node"
                | "PipeWire:Interface:Device"
                | "PipeWire:Interface:Port"
                | "PipeWire:Interface:Link"
        ) {
            continue;
        }
        let p = props(row)?;
        let serial = serial(p)?;
        if !global_serials.insert(serial) {
            return Err(invalid("duplicate PipeWire object serial"));
        }
        match object_type {
            "PipeWire:Interface:Node" => {
                let Some(class) = p.get("media.class").and_then(Value::as_str) else {
                    continue;
                };
                let class = match class {
                    "Audio/Sink" => "Audio/Sink",
                    "Audio/Source" => "Audio/Source",
                    "Stream/Output/Audio" => "Stream/Output/Audio",
                    "Stream/Input/Audio" => "Stream/Input/Audio",
                    _ => continue,
                };
                if nodes.len() >= MAX_AUDIO_NODES {
                    return Err(invalid("PipeWire audio node budget exceeded"));
                }
                let node_name = p
                    .get("node.name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("audio node missing name"))?;
                if p.get("device.id").is_some() {
                    attached_devices.insert(property_u32(p, "device.id")?);
                }
                let object = AudioObject {
                    kind: Kind::Node,
                    id,
                    serial,
                    name: label(node_name)?,
                    media_class: Some(class),
                    parent_node: None,
                    direction: None,
                    output_node: None,
                    input_node: None,
                    output_port: None,
                    input_port: None,
                };
                nodes.insert(id, object);
            }
            "PipeWire:Interface:Device" => {
                if let Some(name) = p.get("device.name").and_then(Value::as_str) {
                    devices.push(AudioObject {
                        kind: Kind::Device,
                        id,
                        serial,
                        name: label(name)?,
                        media_class: None,
                        parent_node: None,
                        direction: None,
                        output_node: None,
                        input_node: None,
                        output_port: None,
                        input_port: None,
                    });
                }
            }
            "PipeWire:Interface:Port" => {
                let parent_node = property_u32(p, "node.id")?;
                if !audio_node_ids.contains(&parent_node) {
                    continue;
                }
                let name = p
                    .get("port.name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("audio port missing name"))?;
                let direction = match p.get("port.direction").and_then(Value::as_str) {
                    Some("in") => "in",
                    Some("out") => "out",
                    _ => return Err(invalid("invalid PipeWire port direction")),
                };
                ports.push(AudioObject {
                    kind: Kind::Port,
                    id,
                    serial,
                    name: label(name)?,
                    media_class: None,
                    parent_node: Some(parent_node),
                    direction: Some(direction),
                    output_node: None,
                    input_node: None,
                    output_port: None,
                    input_port: None,
                });
            }
            "PipeWire:Interface:Link" => {
                let output_node = property_u32(p, "link.output.node")?;
                let input_node = property_u32(p, "link.input.node")?;
                if !audio_node_ids.contains(&output_node) || !audio_node_ids.contains(&input_node) {
                    continue;
                }
                links.push(AudioObject {
                    kind: Kind::Link,
                    id,
                    serial,
                    name: "PipeWire audio link".into(),
                    media_class: None,
                    parent_node: None,
                    direction: None,
                    output_node: Some(output_node),
                    input_node: Some(input_node),
                    output_port: Some(property_u32(p, "link.output.port")?),
                    input_port: Some(property_u32(p, "link.input.port")?),
                });
            }
            _ => return Err(invalid("unhandled PipeWire object type")),
        }
    }

    let mut objects: Vec<AudioObject> = nodes.values().cloned().collect();
    // Only audio-related ports and links are projected. Never imply an
    // incomplete link set represents a privacy or access-control guarantee.
    let live_ports: BTreeMap<u32, AudioObject> = ports
        .iter()
        .filter(|port| port.parent_node.is_some_and(|id| nodes.contains_key(&id)))
        .map(|port| (port.id, port.clone()))
        .collect();
    objects.extend(
        ports
            .into_iter()
            .filter(|port| live_ports.contains_key(&port.id)),
    );
    for link in links {
        let (Some(output), Some(input), Some(output_port), Some(input_port)) = (
            link.output_node,
            link.input_node,
            link.output_port,
            link.input_port,
        ) else {
            return Err(invalid("incomplete PipeWire link identity"));
        };
        if !nodes.contains_key(&output) || !nodes.contains_key(&input) {
            continue;
        }
        let out_port = live_ports
            .get(&output_port)
            .ok_or_else(|| invalid("PipeWire audio link missing output port"))?;
        let in_port = live_ports
            .get(&input_port)
            .ok_or_else(|| invalid("PipeWire audio link missing input port"))?;
        if out_port.parent_node != Some(output)
            || out_port.direction != Some("out")
            || in_port.parent_node != Some(input)
            || in_port.direction != Some("in")
        {
            return Err(invalid("PipeWire audio link endpoint identity mismatch"));
        }
        objects.push(link);
    }
    objects.extend(
        devices
            .into_iter()
            .filter(|device| attached_devices.contains(&device.id)),
    );
    if objects.len() > MAX_GRAPH_OBJECTS {
        return Err(invalid("PipeWire graph projection exceeds resource budget"));
    }
    objects.sort_by_key(|object| (object.kind.as_str(), object.id));
    Ok(objects)
}

fn pipe_limit(reader: impl Read, bound: u64) -> Result<Vec<u8>, ProviderError> {
    let mut data = Vec::new();
    reader
        .take(bound + 1)
        .read_to_end(&mut data)
        .map_err(|_| ProviderError::Unavailable("PipeWire snapshot read failed".into()))?;
    if data.len() as u64 > bound {
        return Err(invalid("PipeWire native snapshot exceeded byte budget"));
    }
    Ok(data)
}

fn dump_current_session() -> Result<String, ProviderError> {
    let runtime = wireplumber_runtime_dir()?;
    let metadata = fs::metadata(std::path::PathBuf::from(&runtime))
        .map_err(|_| ProviderError::Unavailable("PipeWire runtime is inaccessible".into()))?;
    if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(ProviderError::Unavailable(
            "PipeWire runtime directory is not isolated to current user".into(),
        ));
    }
    let mut child = Command::new(EXECUTABLE)
        .arg("--no-colors")
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ProviderError::Unavailable("cannot start native PipeWire dumper".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProviderError::Internal("PipeWire stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProviderError::Internal("PipeWire stderr unavailable".into()))?;
    let output_reader = thread::spawn(move || pipe_limit(stdout, MAX_JSON));
    let error_reader = thread::spawn(move || pipe_limit(stderr, 16 * 1024));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= DEADLINE {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = output_reader.join();
                    let _ = error_reader.join();
                    return Err(ProviderError::Unavailable(
                        "PipeWire snapshot timed out".into(),
                    ));
                }
                thread::sleep(POLL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = output_reader.join();
                let _ = error_reader.join();
                return Err(ProviderError::Unavailable(
                    "PipeWire snapshot wait failed".into(),
                ));
            }
        }
    };
    let output = output_reader
        .join()
        .map_err(|_| ProviderError::Internal("PipeWire output reader panicked".into()))??;
    error_reader
        .join()
        .map_err(|_| ProviderError::Internal("PipeWire error reader panicked".into()))??;
    if !status.success() {
        return Err(ProviderError::Unavailable(
            "PipeWire native snapshot failed".into(),
        ));
    }
    String::from_utf8(output).map_err(|_| invalid("PipeWire JSON is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"[
        {"id":10,"type":"PipeWire:Interface:Node","info":{"props":{
            "object.serial":"100","device.id":"15","node.name":"sink<&","media.class":"Audio/Sink"}}},
        {"id":11,"type":"PipeWire:Interface:Node","info":{"props":{
            "object.serial":"101","node.name":"player","media.class":"Stream/Output/Audio"}}},
        {"id":12,"type":"PipeWire:Interface:Port","info":{"props":{
            "object.serial":"102","node.id":"11","port.name":"output",
            "port.direction":"out"}}},
        {"id":13,"type":"PipeWire:Interface:Port","info":{"props":{
            "object.serial":"103","node.id":"10","port.name":"input",
            "port.direction":"in"}}},
        {"id":14,"type":"PipeWire:Interface:Link","info":{"props":{
            "object.serial":"104","link.output.node":"11","link.output.port":"12",
            "link.input.node":"10","link.input.port":"13"}}},
        {"id":15,"type":"PipeWire:Interface:Device","info":{"props":{
            "object.serial":"105","device.name":"dummy.card"}}}
    ]"#;

    #[test]
    fn audio_graph_projects_typed_nodes_ports_and_real_links() {
        let graph = parse_snapshot(FIXTURE).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(graph.len(), 6);
        assert_eq!(graph.iter().filter(|o| o.kind == Kind::Node).count(), 2);
        let link = graph
            .iter()
            .find(|o| o.kind == Kind::Link)
            .unwrap_or_else(|| unreachable!("expected audio link"));
        assert_eq!(link.output_node, Some(11));
        assert_eq!(link.input_node, Some(10));
        let sink = graph
            .iter()
            .find(|o| o.id == 10)
            .unwrap_or_else(|| unreachable!("expected sink"));
        assert_eq!(
            sink.attributes().get("name_escaped"),
            Some(&ObservedValue::Text("sink&lt;&amp;".into()))
        );
        assert_eq!(
            sink.attributes().get("capture_privacy_verified"),
            Some(&ObservedValue::Bool(false))
        );
    }

    #[test]
    fn audio_graph_rejects_reused_ids_serials_and_broken_links() {
        assert!(parse_snapshot(&FIXTURE.replace("\"id\":15", "\"id\":10")).is_err());
        assert!(parse_snapshot(&FIXTURE.replace("\"105\"", "\"100\"")).is_err());
        assert!(
            parse_snapshot(
                &FIXTURE.replace("\"link.input.port\":\"13\"", "\"link.input.port\":\"12\"")
            )
            .is_err()
        );
        assert!(
            parse_snapshot(
                &FIXTURE.replace("\"node.name\":\"sink<&\"", "\"node.name\":\"bad\\nname\"")
            )
            .is_err()
        );
        assert!(
            parse_snapshot(
                &FIXTURE.replace("\"object.serial\":\"100\"", "\"object.serial\":\"0100\"")
            )
            .is_err()
        );
    }

    #[test]
    fn capture_nodes_are_observed_but_never_claim_hardware_privacy() {
        let source = r#"[
            {"id":20,"type":"PipeWire:Interface:Node","info":{"props":{
                "object.serial":"200","node.name":"capture-source","media.class":"Audio/Source"}}},
            {"id":21,"type":"PipeWire:Interface:Node","info":{"props":{
                "object.serial":"201","node.name":"recorder","media.class":"Stream/Input/Audio"}}}
        ]"#;
        let graph = parse_snapshot(source).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(graph.len(), 2);
        assert_eq!(graph[0].media_class, Some("Audio/Source"));
        assert_eq!(graph[1].media_class, Some("Stream/Input/Audio"));
        for node in &graph {
            assert_eq!(
                node.attributes().get("capture_privacy_verified"),
                Some(&ObservedValue::Bool(false))
            );
        }
    }

    #[test]
    fn foreign_video_nodes_are_not_exposed_as_audio() {
        let video = r#"[
            {"id":20,"type":"PipeWire:Interface:Node","info":{"props":{
                "object.serial":"200","node.name":"camera","media.class":"Video/Source"}}}
        ]"#;
        let graph = parse_snapshot(video).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(graph.is_empty());
    }

    #[test]
    fn audio_graph_resources_pin_exact_serial_and_reject_aliases() {
        let graph = parse_snapshot(FIXTURE).unwrap_or_else(|e| unreachable!("{e}"));
        let sink = graph
            .iter()
            .find(|o| o.id == 10)
            .unwrap_or_else(|| unreachable!("expected sink"));
        assert_eq!(
            sink.resource().map(|v| v.as_str().to_owned()),
            Ok("audio:graph:node:10:100".into())
        );
        for invalid_resource in [
            "audio:graph:node:010:100",
            "audio:graph:node:10:0100",
            "audio:graph:default:10:100",
            "audio:graph:node:10:100:extra",
            "audio:session:output:10",
        ] {
            let id =
                ResourceId::new(invalid_resource).unwrap_or_else(|error| unreachable!("{error}"));
            assert!(parse_resource(&id).is_err());
        }
    }
}
