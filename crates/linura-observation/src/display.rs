//! Typed projection of the canonical observation envelope, never a second
//! observation authority. Native instance/output-generation attestation remains
//! the adapter's responsibility; constructing attributes conveys no authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use linura_core::{
    DisplayLayout, DisplayMode, DisplayOutputId, DisplayOutputLayout, DisplayOutputSet,
    DisplayTopologyId, NativeOutputCapabilities,
};

use crate::{ObservationAuthority, ObservationEnvelope, ObservedValue};

pub const DISPLAY_PROVIDER: &str = "hyprland";
pub const DISPLAY_OUTPUTS_CAPABILITY: &str = "display.outputs.observe";
pub const DISPLAY_COVERAGE_CAPABILITY: &str = "session.display-coverage.observe";
const MAX_VALID_FOR_MS: u64 = 2_000;
const MAX_ATTRIBUTES: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayObservationFacts {
    inventory: DisplayOutputSet,
    capabilities: Vec<NativeOutputCapabilities>,
    layout: DisplayLayout,
    powered: BTreeSet<DisplayOutputId>,
}

impl DisplayObservationFacts {
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        expected: &DisplayTopologyId,
        now_unix_ms: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_PROVIDER
            || observation.capability.as_str() != DISPLAY_OUTPUTS_CAPABILITY
            || observation.resource
                != expected
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        if observation.observed_at_unix_ms == 0
            || observation.valid_for_ms == 0
            || observation.valid_for_ms > MAX_VALID_FOR_MS
            || observation
                .observed_at_unix_ms
                .checked_add(observation.valid_for_ms)
                .is_none()
            || now_unix_ms
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|elapsed| elapsed >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let attributes = &observation.attributes;
        if attributes.len() > MAX_ATTRIBUTES || number(attributes, "display_schema")? != 1 {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attributes, "output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let mut outputs = Vec::new();
        let mut capabilities = Vec::new();
        let mut powered = BTreeSet::new();
        for index in 0..count {
            let prefix = format!("output.{index}");
            let output = DisplayOutputId::new(
                expected.clone(),
                number(attributes, &format!("{prefix}.handle"))?,
                number(attributes, &format!("{prefix}.generation"))?,
            )
            .map_err(|_| DisplayEvidenceError::Identity)?;
            let modes = parse_modes(text(attributes, &format!("{prefix}.modes"))?)?;
            let cap = NativeOutputCapabilities::new(
                output.clone(),
                modes,
                boolean(attributes, &format!("{prefix}.can_disable"))?,
            )
            .map_err(|_| DisplayEvidenceError::Shape)?;
            if boolean(attributes, &format!("{prefix}.powered"))? {
                powered.insert(output.clone());
            }
            outputs.push(output);
            capabilities.push(cap);
        }
        let inventory = DisplayOutputSet::new(expected.clone(), outputs)
            .map_err(|_| DisplayEvidenceError::Identity)?;
        let layout = DisplayLayout::from_canonical_text(
            &inventory,
            &capabilities,
            text(attributes, "layout")?,
        )
        .map_err(|_| DisplayEvidenceError::Layout)?;
        // Re-encoding checks the entire shape, types, ordering and power facts.
        // Extra/missing fields cannot silently become ignored authority input.
        if display_observation_attributes(&inventory, &capabilities, &layout, &powered)?
            != *attributes
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            inventory,
            capabilities,
            layout,
            powered,
        })
    }

    #[must_use]
    pub const fn inventory(&self) -> &DisplayOutputSet {
        &self.inventory
    }

    #[must_use]
    pub fn capabilities(&self) -> &[NativeOutputCapabilities] {
        &self.capabilities
    }

    #[must_use]
    pub const fn layout(&self) -> &DisplayLayout {
        &self.layout
    }

    #[must_use]
    pub const fn powered_outputs(&self) -> &BTreeSet<DisplayOutputId> {
        &self.powered
    }

    #[must_use]
    pub fn has_powered_independent_output(&self) -> bool {
        self.layout.outputs().iter().any(|output| matches!(output,
            DisplayOutputLayout::Enabled { output, mirror: None, .. } if self.powered.contains(output)))
    }
}

/// Encode only typed semantic facts inside the existing envelope. No connector
/// labels, OS transport handles, EDID, serials, socket paths or execution credentials.
pub fn display_observation_attributes(
    inventory: &DisplayOutputSet,
    capabilities: &[NativeOutputCapabilities],
    layout: &DisplayLayout,
    powered: &BTreeSet<DisplayOutputId>,
) -> Result<BTreeMap<String, ObservedValue>, DisplayEvidenceError> {
    let validated = DisplayLayout::new(inventory, capabilities, layout.outputs().to_vec())
        .map_err(|_| DisplayEvidenceError::Layout)?;
    if validated != *layout
        || powered.iter().any(|output| {
            !layout
                .outputs()
                .iter()
                .any(|entry| entry.output() == output && entry.enabled())
        })
    {
        return Err(DisplayEvidenceError::Identity);
    }
    let mut attributes = BTreeMap::from([
        ("display_schema".into(), ObservedValue::U64(1)),
        (
            "output_count".into(),
            ObservedValue::U64(inventory.outputs().len() as u64),
        ),
        (
            "layout".into(),
            ObservedValue::Text(
                layout
                    .canonical_text()
                    .map_err(|_| DisplayEvidenceError::Layout)?,
            ),
        ),
    ]);
    // Inventory encoding is deterministic even if native enumeration reordered.
    let mut outputs: Vec<_> = inventory.outputs().iter().collect();
    outputs.sort();
    for (index, output) in outputs.into_iter().enumerate() {
        let prefix = format!("output.{index}");
        let cap = capabilities
            .iter()
            .find(|cap| cap.output() == output)
            .ok_or(DisplayEvidenceError::Shape)?;
        attributes.insert(
            format!("{prefix}.handle"),
            ObservedValue::U64(output.handle()),
        );
        attributes.insert(
            format!("{prefix}.generation"),
            ObservedValue::U64(output.generation()),
        );
        attributes.insert(
            format!("{prefix}.can_disable"),
            ObservedValue::Bool(cap.can_disable()),
        );
        attributes.insert(
            format!("{prefix}.powered"),
            ObservedValue::Bool(powered.contains(output)),
        );
        let modes: Vec<_> = cap
            .modes()
            .iter()
            .map(|mode| {
                format!(
                    "{},{},{}",
                    mode.width(),
                    mode.height(),
                    mode.refresh_millihz()
                )
            })
            .collect();
        attributes.insert(
            format!("{prefix}.modes"),
            ObservedValue::Text(modes.join(";")),
        );
    }
    Ok(attributes)
}

fn parse_modes(value: &str) -> Result<Vec<DisplayMode>, DisplayEvidenceError> {
    if value.len() > 4096 {
        return Err(DisplayEvidenceError::Shape);
    }
    let mut modes = Vec::new();
    for entry in value.split(';') {
        if modes.len() >= 128 {
            return Err(DisplayEvidenceError::Shape);
        }
        let fields: Vec<_> = entry.split(',').collect();
        let [width, height, refresh] = fields.as_slice() else {
            return Err(DisplayEvidenceError::Shape);
        };
        let number = |raw: &str| raw.parse::<u32>().map_err(|_| DisplayEvidenceError::Shape);
        modes.push(
            DisplayMode::new(number(width)?, number(height)?, number(refresh)?)
                .map_err(|_| DisplayEvidenceError::Shape)?,
        );
    }
    Ok(modes)
}

fn number(
    attributes: &BTreeMap<String, ObservedValue>,
    key: &str,
) -> Result<u64, DisplayEvidenceError> {
    match attributes.get(key) {
        Some(ObservedValue::U64(value)) => Ok(*value),
        _ => Err(DisplayEvidenceError::Shape),
    }
}
fn text<'a>(
    attributes: &'a BTreeMap<String, ObservedValue>,
    key: &str,
) -> Result<&'a str, DisplayEvidenceError> {
    match attributes.get(key) {
        Some(ObservedValue::Text(value)) => Ok(value),
        _ => Err(DisplayEvidenceError::Shape),
    }
}
fn boolean(
    attributes: &BTreeMap<String, ObservedValue>,
    key: &str,
) -> Result<bool, DisplayEvidenceError> {
    match attributes.get(key) {
        Some(ObservedValue::Bool(value)) => Ok(*value),
        _ => Err(DisplayEvidenceError::Shape),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayEvidenceError {
    Identity,
    Freshness,
    Shape,
    Layout,
}

impl Display for DisplayEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Identity => "display evidence does not bind the exact native topology",
            Self::Freshness => {
                "display evidence is stale, future or outside the native validity bound"
            }
            Self::Shape => "display evidence is incomplete, ambiguous or unsupported",
            Self::Layout => "display evidence layout is unsupported or inconsistent",
        })
    }
}
impl std::error::Error for DisplayEvidenceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        BootId, CapabilityId, CompositorInvocationId, DisplayScale, DisplayTransform, ProviderId,
        SessionEpoch,
    };

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> (DisplayTopologyId, ObservationEnvelope) {
        let topology = id(DisplayTopologyId::new(
            id(SessionEpoch::new(
                id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
                1000,
                "c2",
                42,
            )),
            "seat0",
            id(CompositorInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            7,
        ));
        let output = id(DisplayOutputId::new(topology.clone(), 0, 1));
        let inventory = id(DisplayOutputSet::new(
            topology.clone(),
            vec![output.clone()],
        ));
        let mode = id(DisplayMode::new(1920, 1080, 60_000));
        let caps = vec![id(NativeOutputCapabilities::new(
            output.clone(),
            vec![mode],
            true,
        ))];
        let layout = id(DisplayLayout::new(
            &inventory,
            &caps,
            vec![DisplayOutputLayout::Enabled {
                output: output.clone(),
                mode,
                scale: id(DisplayScale::new(1000)),
                transform: DisplayTransform::Normal,
                x: 0,
                y: 0,
                mirror: None,
            }],
        ));
        let observation = ObservationEnvelope {
            provider: id(ProviderId::new(DISPLAY_PROVIDER)),
            resource: id(topology.resource_id()),
            capability: id(CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY)),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            sequence: 1,
            attributes: id(display_observation_attributes(
                &inventory,
                &caps,
                &layout,
                &BTreeSet::from([output]),
            )),
        };
        (topology, observation)
    }

    #[test]
    fn canonical_envelope_projects_exact_inventory_layout_modes_and_power() {
        let (topology, observation) = fixture();
        let facts = id(DisplayObservationFacts::from_envelope(
            &observation,
            &topology,
            1100,
        ));
        assert!(facts.has_powered_independent_output());
        assert_eq!(facts.inventory().topology(), &topology);
        assert_eq!(facts.capabilities()[0].modes().len(), 1);
        assert_eq!(
            id(display_observation_attributes(
                facts.inventory(),
                facts.capabilities(),
                facts.layout(),
                facts.powered_outputs()
            )),
            observation.attributes
        );
        let mut off = observation.clone();
        off.attributes
            .insert("output.0.powered".into(), ObservedValue::Bool(false));
        assert!(
            !id(DisplayObservationFacts::from_envelope(
                &off, &topology, 1100
            ))
            .has_powered_independent_output()
        );
    }

    #[test]
    fn missing_wrong_typed_extra_and_noncanonical_fields_fail_closed() {
        let (topology, observation) = fixture();
        for key in observation.attributes.keys() {
            for value in [None, Some(ObservedValue::Text("unsupported".into()))] {
                let mut bad = observation.clone();
                if let Some(value) = value {
                    bad.attributes.insert(key.clone(), value);
                } else {
                    bad.attributes.remove(key);
                }
                assert!(
                    DisplayObservationFacts::from_envelope(&bad, &topology, 1100).is_err(),
                    "{key}"
                );
            }
        }
        for (key, value) in [
            ("output_count", ObservedValue::U64(17)),
            ("output_count", ObservedValue::U64(0)),
            ("output.0.generation", ObservedValue::U64(0)),
            ("display_schema", ObservedValue::U64(2)),
            (
                "output.0.modes",
                ObservedValue::Text("01920,1080,60000".into()),
            ),
            (
                "output.0.modes",
                ObservedValue::Text("1920,1080,60000;1920,1080,60000".into()),
            ),
            ("output.0.modes", ObservedValue::Text("x".repeat(4097))),
            ("ignored", ObservedValue::Bool(true)),
        ] {
            let mut bad = observation.clone();
            bad.attributes.insert(key.into(), value);
            assert!(
                DisplayObservationFacts::from_envelope(&bad, &topology, 1100).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn wrong_authority_identity_generation_and_freshness_cannot_be_promoted() {
        let (topology, observation) = fixture();
        for now in [0, 999, 3000, u64::MAX] {
            assert_eq!(
                DisplayObservationFacts::from_envelope(&observation, &topology, now),
                Err(DisplayEvidenceError::Freshness)
            );
        }
        let mut overflow = observation.clone();
        overflow.observed_at_unix_ms = u64::MAX - 100;
        assert_eq!(
            DisplayObservationFacts::from_envelope(&overflow, &topology, u64::MAX - 50),
            Err(DisplayEvidenceError::Freshness)
        );
        for kind in [
            "provider",
            "capability",
            "resource",
            "authority",
            "sequence",
            "time",
            "validity",
        ] {
            let mut bad = observation.clone();
            match kind {
                "provider" => bad.provider = id(ProviderId::new("session-locker")),
                "capability" => {
                    bad.capability = id(CapabilityId::new("platform.compositor.observe"))
                }
                "resource" => bad.resource = id(topology.session().resource_id()),
                "authority" => bad.authority = ObservationAuthority::SyntheticTest,
                "sequence" => bad.sequence = 0,
                "time" => bad.observed_at_unix_ms = 0,
                _ => bad.valid_for_ms = 2001,
            }
            assert!(DisplayObservationFacts::from_envelope(&bad, &topology, 1100).is_err());
        }
        let replaced = id(DisplayTopologyId::new(
            topology.session().clone(),
            "seat0",
            topology.compositor().clone(),
            8,
        ));
        assert_eq!(
            DisplayObservationFacts::from_envelope(&observation, &replaced, 1100),
            Err(DisplayEvidenceError::Identity)
        );
    }
}
