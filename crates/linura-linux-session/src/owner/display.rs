//! One bounded native owner probe. The private DTO is decoded into the existing
//! canonical envelopes, not retained as another observation or identity authority.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use linura_core::{
    CapabilityId, CompositorInvocationId, DisplayLayout, DisplayMode, DisplayOutputId,
    DisplayOutputLayout, DisplayOutputSet, DisplayScale, DisplayTopologyId, DisplayTransform,
    NativeOutputCapabilities, ProviderId, SessionLockId,
};
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER, ObservationEnvelope,
    ObservedValue, display_observation_attributes,
};
use serde::Deserialize;

use super::{
    ENDPOINT, INTERFACE, NativeSessionChannel, NativeSessionRole, boot_ms, current_boot,
    observation, owner_reply_budget, unix_ms,
};

type Wire = (String, String, String, u64, String, String, bool);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Topology {
    schema: u32,
    generation: String,
    heads: Vec<Head>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    handle: String,
    generation: String,
    name: String,
    enabled: bool,
    covered: bool,
    modes: Vec<[u32; 3]>,
    #[serde(deserialize_with = "required_current_mode")]
    current_mode: Option<[u32; 3]>,
    x: i32,
    y: i32,
    transform: u32,
    scale_fixed: i32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Monitor {
    id: u64,
    name: String,
    disabled: bool,
    dpms_status: bool,
    mirror_of: String,
}

fn required_current_mode<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u32; 3]>, D::Error> {
    Option::<[u32; 3]>::deserialize(deserializer)
}

fn number(value: &str) -> Result<u64, String> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("native display identity is malformed".into());
    }
    let parsed: u64 = value
        .parse()
        .map_err(|_| "native display identity overflow")?;
    if parsed.to_string() != value {
        return Err("native display identity is not canonical".into());
    }
    Ok(parsed)
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn mode(value: [u32; 3]) -> Result<DisplayMode, String> {
    DisplayMode::new(value[0], value[1], value[2]).map_err(|e| e.to_string())
}

/// Native peer, boot, session, supervisor invocation and deadline must already
/// have been revalidated by the channel. This decoder grants no authority.
fn project(
    mut coverage: ObservationEnvelope,
    compositor: &str,
    seat: &str,
    topology: &str,
    monitors: &str,
) -> Result<(ObservationEnvelope, ObservationEnvelope), String> {
    if topology.len() > 64 * 1024 || monitors.len() > 256 * 1024 || coverage.sequence == 0 {
        return Err("native display data exceeds its bound".into());
    }
    let lock = SessionLockId::from_resource(&coverage.resource).map_err(|e| e.to_string())?;
    let native: Topology =
        serde_json::from_str(topology).map_err(|_| "native display topology is malformed")?;
    let metadata: Vec<Monitor> =
        serde_json::from_str(monitors).map_err(|_| "native display metadata is malformed")?;
    if native.schema != 1
        || native.heads.is_empty()
        || native.heads.len() > 16
        || metadata.len() != native.heads.len()
    {
        return Err("native display inventory is incomplete or unsupported".into());
    }
    let topology = DisplayTopologyId::new(
        lock.epoch().clone(),
        seat,
        CompositorInvocationId::new(compositor).map_err(|e| e.to_string())?,
        number(&native.generation)?,
    )
    .map_err(|e| e.to_string())?;
    let mut by_name = BTreeMap::new();
    let mut native_ids = BTreeSet::new();
    for monitor in &metadata {
        if !name(&monitor.name)
            || !native_ids.insert(monitor.id)
            || by_name.insert(monitor.name.as_str(), monitor).is_some()
        {
            return Err("native display monitor identity is ambiguous".into());
        }
    }
    let mut names = BTreeSet::new();
    let mut handles = BTreeSet::new();
    let mut identities = BTreeMap::new();
    for head in &native.heads {
        if !name(&head.name)
            || !names.insert(head.name.as_str())
            || !by_name.contains_key(head.name.as_str())
        {
            return Err("native display head identity is ambiguous".into());
        }
        let output = DisplayOutputId::new(
            topology.clone(),
            number(&head.handle)?,
            number(&head.generation)?,
        )
        .map_err(|e| e.to_string())?;
        if !handles.insert(output.handle()) {
            return Err("native display handle is duplicated".into());
        }
        identities.insert(by_name[head.name.as_str()].id, output);
    }
    let mut layouts = Vec::new();
    let mut capabilities = Vec::new();
    let mut powered = BTreeSet::new();
    let mut active = BTreeMap::new();
    let mut covered = BTreeMap::new();
    let secure = match coverage.attributes.get("secure") {
        Some(ObservedValue::Bool(value)) => *value,
        _ => return Err("native lock state is unsupported".into()),
    };
    for head in &native.heads {
        let metadata = by_name[head.name.as_str()];
        let output = identities[&metadata.id].clone();
        if metadata.disabled == head.enabled
            || (!secure && head.covered)
            || (!head.enabled && head.covered)
        {
            return Err("independent native display sources disagree".into());
        }
        let modes = head
            .modes
            .iter()
            .copied()
            .map(mode)
            .collect::<Result<Vec<_>, _>>()?;
        capabilities.push(
            NativeOutputCapabilities::new(output.clone(), modes, true)
                .map_err(|e| e.to_string())?,
        );
        let mirror = if metadata.mirror_of == "none" {
            None
        } else {
            Some(
                identities
                    .get(&number(&metadata.mirror_of)?)
                    .ok_or("native mirror refers to an absent output")?
                    .clone(),
            )
        };
        if head.enabled {
            let mode = mode(head.current_mode.ok_or("native current mode is missing")?)?;
            let scale = u32::try_from(head.scale_fixed).map_err(|_| "native scale is invalid")?;
            let milli = scale.checked_mul(1000).ok_or("native scale overflow")?;
            if milli % 256 != 0 {
                return Err("native scale has unsupported exact precision".into());
            }
            let row = DisplayOutputLayout::Enabled {
                output: output.clone(),
                mode,
                scale: DisplayScale::new(milli / 256).map_err(|e| e.to_string())?,
                transform: DisplayTransform::from_native(head.transform)
                    .map_err(|e| e.to_string())?,
                x: head.x,
                y: head.y,
                mirror,
            };
            active.insert(
                output.handle(),
                format!("{}:{}", output.handle(), output.generation()),
            );
            if head.covered {
                covered.insert(
                    output.handle(),
                    format!("{}:{}", output.handle(), output.generation()),
                );
            }
            if metadata.dpms_status {
                powered.insert(output.clone());
            }
            layouts.push(row);
        } else {
            if head.current_mode.is_some()
                || head.scale_fixed != 0
                || head.transform != 0
                || head.x != 0
                || head.y != 0
                || mirror.is_some()
            {
                return Err("disabled native display retains current layout state".into());
            }
            layouts.push(DisplayOutputLayout::Disabled { output });
        }
    }
    let inventory = DisplayOutputSet::new(topology.clone(), identities.into_values().collect())
        .map_err(|e| e.to_string())?;
    let layout =
        DisplayLayout::new(&inventory, &capabilities, layouts).map_err(|e| e.to_string())?;
    let attributes = display_observation_attributes(&inventory, &capabilities, &layout, &powered)
        .map_err(|e| e.to_string())?;
    let display = ObservationEnvelope {
        provider: ProviderId::new(DISPLAY_PROVIDER).map_err(|e| e.to_string())?,
        capability: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY).map_err(|e| e.to_string())?,
        resource: topology.resource_id().map_err(|e| e.to_string())?,
        attributes,
        authority: coverage.authority,
        observed_at_unix_ms: coverage.observed_at_unix_ms,
        valid_for_ms: coverage.valid_for_ms,
        sequence: coverage.sequence,
    };
    coverage.capability =
        CapabilityId::new(DISPLAY_COVERAGE_CAPABILITY).map_err(|e| e.to_string())?;
    coverage.attributes.extend([
        (
            "display_topology".into(),
            ObservedValue::Text(display.resource.as_str().into()),
        ),
        (
            "observed_outputs".into(),
            ObservedValue::Text(active.into_values().collect::<Vec<_>>().join(",")),
        ),
        (
            "covered_outputs".into(),
            ObservedValue::Text(covered.into_values().collect::<Vec<_>>().join(",")),
        ),
    ]);
    Ok((display, coverage))
}

impl NativeSessionChannel {
    fn native_display_sample(
        &self,
        uid: u32,
        sequence: u64,
    ) -> Result<(ObservationEnvelope, ObservationEnvelope), String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let boot = current_boot()?;
        let identity = self.discover(uid, started)?;
        let reply = self.call_with_budget(
            &identity.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObserveDisplay",
            &(),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply.body().signature().to_string() != "(ssstssb)" {
            return Err("native display observation signature mismatch".into());
        }
        let ((resource, compositor, seat, sampled_boot_ms, topology, monitors, secure),): (Wire,) =
            reply
                .body()
                .deserialize()
                .map_err(|_| "native display observation codec mismatch")?;
        self.revalidate_observation(&identity, &boot, started)?;
        let now = unix_ms()?;
        let coverage = observation(
            &identity,
            &boot,
            &resource,
            secure,
            sampled_boot_ms,
            boot_ms()?,
            now,
            sequence,
        )?;
        let result = project(coverage, &compositor, &seat, &topology, &monitors)?;
        if started.elapsed() >= crate::bus::PROBE_BUDGET {
            return Err("native display observation exceeded its original deadline".into());
        }
        result
            .0
            .require_current(unix_ms()?)
            .map_err(|e| e.to_string())?;
        Ok(result)
    }
    pub fn observe_current_display(
        &self,
        uid: u32,
        sequence: u64,
    ) -> Result<(ObservationEnvelope, SessionLockId), String> {
        let (display, coverage) = self.native_display_sample(uid, sequence)?;
        let lock = SessionLockId::from_resource(&coverage.resource).map_err(|e| e.to_string())?;
        Ok((display, lock))
    }
    pub fn observe_display(
        &self,
        expected: &DisplayTopologyId,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        let (display, _) = self.native_display_sample(expected.session().uid(), sequence)?;
        if display.resource != expected.resource_id().map_err(|e| e.to_string())? {
            return Err("native display topology generation was replaced".into());
        }
        Ok(display)
    }
    pub fn observe_display_coverage(
        &self,
        expected: &SessionLockId,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        let (_, coverage) = self.native_display_sample(expected.epoch().uid(), sequence)?;
        if coverage.resource != expected.resource_id().map_err(|e| e.to_string())? {
            return Err("native display lock generation was replaced".into());
        }
        Ok(coverage)
    }
}

#[cfg(test)]
mod tests;
