//! S21 deterministic candidate display layout validation.
//!
//! This module has no native executor or authorization mechanism. It rejects
//! incomplete, ambiguous and potentially invisible candidate layouts BEFORE
//! Control could consider their effect. It does not prove lock coverage,
//! independent native mode support, physical visibility or rollback readiness.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use crate::{DisplayOutputId, DisplayOutputSet, DisplayTopologyId};

const MAX_SCREEN_AXIS: u32 = 32_768;
const MAX_LAYOUT_ABS_POSITION: i32 = 65_536;
const MAX_REFRESH_MILLIHZ: u32 = 1_000_000;
const MAX_SUPPORTED_MODES: usize = 128;
const MIN_SCALE_MILLI: u32 = 500;
const MAX_SCALE_MILLI: u32 = 4_000;

/// Exact native size and refresh tuple; no floating-point normalization.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayMode {
    width: u32,
    height: u32,
    refresh_millihz: u32,
}

impl DisplayMode {
    pub fn new(width: u32, height: u32, refresh_millihz: u32) -> Result<Self, DisplayLayoutError> {
        if width == 0
            || height == 0
            || width > MAX_SCREEN_AXIS
            || height > MAX_SCREEN_AXIS
            || refresh_millihz == 0
            || refresh_millihz > MAX_REFRESH_MILLIHZ
        {
            return Err(DisplayLayoutError::InvalidMode);
        }
        Ok(Self {
            width,
            height,
            refresh_millihz,
        })
    }

    #[must_use]
    pub const fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub const fn height(self) -> u32 {
        self.height
    }

    #[must_use]
    pub const fn refresh_millihz(self) -> u32 {
        self.refresh_millihz
    }
}

/// Fixed-point scale; XDG/QML float strings cannot bypass exact validation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayScale(u32);

impl DisplayScale {
    pub fn new(milli: u32) -> Result<Self, DisplayLayoutError> {
        if !(MIN_SCALE_MILLI..=MAX_SCALE_MILLI).contains(&milli) {
            return Err(DisplayLayoutError::InvalidScale);
        }
        Ok(Self(milli))
    }

    #[must_use]
    pub const fn milli(self) -> u32 {
        self.0
    }
}

/// The transform set is closed and explicitly listed; arbitrary compositor
/// commands or unbounded rotation strings are not accepted as display plans.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DisplayTransform {
    Normal,
    Rotate90,
    Rotate180,
    Rotate270,
    Flip,
    FlipRotate90,
    FlipRotate180,
    FlipRotate270,
}

impl DisplayTransform {
    /// Closed native transform vocabulary shared by adapters and validation.
    pub fn from_native(value: u32) -> Result<Self, DisplayLayoutError> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Rotate90),
            2 => Ok(Self::Rotate180),
            3 => Ok(Self::Rotate270),
            4 => Ok(Self::Flip),
            5 => Ok(Self::FlipRotate90),
            6 => Ok(Self::FlipRotate180),
            7 => Ok(Self::FlipRotate270),
            _ => Err(DisplayLayoutError::InvalidTransform),
        }
    }

    #[must_use]
    pub const fn native_value(self) -> u32 {
        match self {
            Self::Normal => 0,
            Self::Rotate90 => 1,
            Self::Rotate180 => 2,
            Self::Rotate270 => 3,
            Self::Flip => 4,
            Self::FlipRotate90 => 5,
            Self::FlipRotate180 => 6,
            Self::FlipRotate270 => 7,
        }
    }

    #[must_use]
    pub const fn swaps_axes(self) -> bool {
        matches!(
            self,
            Self::Rotate90 | Self::Rotate270 | Self::FlipRotate90 | Self::FlipRotate270
        )
    }
}

/// Native provider-reported options for exactly one output generation.
/// These are candidates, not authority to act on the output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOutputCapabilities {
    output: DisplayOutputId,
    modes: BTreeSet<DisplayMode>,
    can_disable: bool,
}

impl NativeOutputCapabilities {
    pub fn new(
        output: DisplayOutputId,
        modes: Vec<DisplayMode>,
        can_disable: bool,
    ) -> Result<Self, DisplayLayoutError> {
        if modes.is_empty() || modes.len() > MAX_SUPPORTED_MODES {
            return Err(DisplayLayoutError::InvalidSupportedModes);
        }
        let unique: BTreeSet<_> = modes.iter().copied().collect();
        if unique.len() != modes.len() {
            return Err(DisplayLayoutError::DuplicateMode);
        }
        Ok(Self {
            output,
            modes: unique,
            can_disable,
        })
    }

    #[must_use]
    pub const fn output(&self) -> &DisplayOutputId {
        &self.output
    }

    #[must_use]
    pub fn modes(&self) -> &BTreeSet<DisplayMode> {
        &self.modes
    }

    #[must_use]
    pub const fn can_disable(&self) -> bool {
        self.can_disable
    }
}

/// One explicit output's target state. A disabled output is not allowed to
/// retain stale target geometry. Mirroring is exact within the same topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayOutputLayout {
    Disabled {
        output: DisplayOutputId,
    },
    Enabled {
        output: DisplayOutputId,
        mode: DisplayMode,
        scale: DisplayScale,
        transform: DisplayTransform,
        x: i32,
        y: i32,
        mirror: Option<DisplayOutputId>,
    },
}

impl DisplayOutputLayout {
    #[must_use]
    pub const fn output(&self) -> &DisplayOutputId {
        match self {
            Self::Disabled { output } | Self::Enabled { output, .. } => output,
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }
}

/// Fully specified output layout, preserving the exact current observed
/// topology. An incomplete request is rejected, never merged with stale
/// cached output state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayout {
    topology: DisplayTopologyId,
    outputs: Vec<DisplayOutputLayout>,
}

impl DisplayLayout {
    /// Canonical typed desired-state material for the planner and durable
    /// journals. This is data, never a compositor command or execution permit.
    pub fn canonical_text(&self) -> Result<String, DisplayLayoutError> {
        let resource = self
            .topology
            .resource_id()
            .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
        let mut text = format!("LNDL:1;{};", resource.as_str());
        for entry in &self.outputs {
            let output = entry.output();
            text.push_str(&format!("{}:{}:", output.handle(), output.generation()));
            match entry {
                DisplayOutputLayout::Disabled { .. } => text.push_str("disabled;"),
                DisplayOutputLayout::Enabled {
                    mode,
                    scale,
                    transform,
                    x,
                    y,
                    mirror,
                    ..
                } => {
                    let mirror = mirror.as_ref().map_or_else(
                        || "-".into(),
                        |target| format!("{},{}", target.handle(), target.generation()),
                    );
                    text.push_str(&format!(
                        "enabled:{}:{}:{}:{}:{}:{x}:{y}:{mirror};",
                        mode.width(),
                        mode.height(),
                        mode.refresh_millihz(),
                        scale.milli(),
                        transform.native_value()
                    ));
                }
            }
        }
        Ok(text)
    }

    /// Parse only against the complete current inventory and native options.
    /// Exact re-encoding rejects aliases, reordered/duplicate rows, old schema
    /// generations and extra material instead of normalizing approved intent.
    pub fn from_canonical_text(
        observed: &DisplayOutputSet,
        capabilities: &[NativeOutputCapabilities],
        text: &str,
    ) -> Result<Self, DisplayLayoutError> {
        if text.len() > 4096 || !text.ends_with(';') {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let mut lines = text[..text.len() - 1].split(';');
        if lines.next() != Some("LNDL:1")
            || lines.next()
                != Some(
                    observed
                        .topology()
                        .resource_id()
                        .map_err(|_| DisplayLayoutError::InvalidEncoding)?
                        .as_str(),
                )
        {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let lookup = |handle: &str, generation: &str| {
            let handle = handle
                .parse::<u64>()
                .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
            let generation = generation
                .parse::<u64>()
                .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
            observed
                .outputs()
                .iter()
                .find(|output| output.handle() == handle && output.generation() == generation)
                .cloned()
                .ok_or(DisplayLayoutError::ForeignOutput)
        };
        let number = |value: &str| {
            value
                .parse::<u32>()
                .map_err(|_| DisplayLayoutError::InvalidEncoding)
        };
        let position = |value: &str| {
            value
                .parse::<i32>()
                .map_err(|_| DisplayLayoutError::InvalidEncoding)
        };
        let mut outputs = Vec::new();
        for line in lines {
            if outputs.len() >= observed.outputs().len() {
                return Err(DisplayLayoutError::InvalidEncoding);
            }
            let fields: Vec<_> = line.split(':').collect();
            let entry = match fields.as_slice() {
                [handle, generation, "disabled"] => DisplayOutputLayout::Disabled {
                    output: lookup(handle, generation)?,
                },
                [
                    handle,
                    generation,
                    "enabled",
                    width,
                    height,
                    refresh,
                    scale,
                    transform,
                    x,
                    y,
                    mirror,
                ] => {
                    let mirror = if *mirror == "-" {
                        None
                    } else {
                        let (handle, generation) = mirror
                            .split_once(',')
                            .ok_or(DisplayLayoutError::InvalidEncoding)?;
                        Some(lookup(handle, generation)?)
                    };
                    DisplayOutputLayout::Enabled {
                        output: lookup(handle, generation)?,
                        mode: DisplayMode::new(number(width)?, number(height)?, number(refresh)?)?,
                        scale: DisplayScale::new(number(scale)?)?,
                        transform: DisplayTransform::from_native(number(transform)?)?,
                        x: position(x)?,
                        y: position(y)?,
                        mirror,
                    }
                }
                _ => return Err(DisplayLayoutError::InvalidEncoding),
            };
            outputs.push(entry);
        }
        let result = Self::new(observed, capabilities, outputs)?;
        if result.canonical_text()? != text {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        Ok(result)
    }

    pub fn new(
        observed: &DisplayOutputSet,
        capabilities: &[NativeOutputCapabilities],
        outputs: Vec<DisplayOutputLayout>,
    ) -> Result<Self, DisplayLayoutError> {
        let expected = observed.outputs();
        if expected.is_empty()
            || outputs.len() != expected.len()
            || capabilities.len() != expected.len()
        {
            return Err(DisplayLayoutError::IncompleteTopology);
        }
        let mut observed_ids = BTreeSet::new();
        for output in expected {
            if !observed_ids.insert(output.clone()) {
                return Err(DisplayLayoutError::AmbiguousOutput);
            }
        }
        let mut native = BTreeMap::new();
        for cap in capabilities {
            if !observed_ids.contains(cap.output()) {
                return Err(DisplayLayoutError::ForeignOutput);
            }
            if native.insert(cap.output().clone(), cap).is_some() {
                return Err(DisplayLayoutError::AmbiguousOutput);
            }
        }
        if native.len() != observed_ids.len() {
            return Err(DisplayLayoutError::IncompleteTopology);
        }

        let mut result = BTreeMap::new();
        let mut visible = 0_usize;
        for layout in outputs {
            let id = layout.output().clone();
            let caps = native.get(&id).ok_or(DisplayLayoutError::ForeignOutput)?;
            if result.contains_key(&id) {
                return Err(DisplayLayoutError::AmbiguousOutput);
            }
            match &layout {
                DisplayOutputLayout::Disabled { .. } if !caps.can_disable() => {
                    return Err(DisplayLayoutError::UnsupportedDisable);
                }
                DisplayOutputLayout::Disabled { .. } => {}
                DisplayOutputLayout::Enabled {
                    mode,
                    scale,
                    transform,
                    x,
                    y,
                    mirror,
                    ..
                } => {
                    if !caps.modes().contains(mode) {
                        return Err(DisplayLayoutError::UnsupportedMode);
                    }
                    // Defense in depth: scale is already bounded by its constructor.
                    if !(MIN_SCALE_MILLI..=MAX_SCALE_MILLI).contains(&scale.milli()) {
                        return Err(DisplayLayoutError::InvalidScale);
                    }
                    if x.unsigned_abs() > MAX_LAYOUT_ABS_POSITION as u32
                        || y.unsigned_abs() > MAX_LAYOUT_ABS_POSITION as u32
                    {
                        return Err(DisplayLayoutError::InvalidPosition);
                    }
                    // The transformed scaled extent must fit finite i32 geometry.
                    let (width, height) = if transform.swaps_axes() {
                        (mode.height(), mode.width())
                    } else {
                        (mode.width(), mode.height())
                    };
                    // Round outward: truncation can accept an extent just over
                    // the supported limit. This is a bound, not native rounding
                    // or proof that the compositor supports a particular scale.
                    let max_width = (u64::from(width) * 1000).div_ceil(u64::from(scale.milli()));
                    let max_height = (u64::from(height) * 1000).div_ceil(u64::from(scale.milli()));
                    if max_width == 0
                        || max_height == 0
                        || max_width > u64::from(MAX_SCREEN_AXIS)
                        || max_height > u64::from(MAX_SCREEN_AXIS)
                    {
                        return Err(DisplayLayoutError::InvalidGeometry);
                    }
                    if let Some(target) = mirror {
                        if target == &id || !observed_ids.contains(target) {
                            return Err(DisplayLayoutError::InvalidMirror);
                        }
                    } else {
                        visible += 1;
                    }
                }
            }
            result.insert(id, layout);
        }

        // Every mirrored target must be an independently enabled root. No
        // chains/cycles, and never mirror an output that is disabled. Mirrors
        // share their root's logical origin; an independent position would
        // describe a different layout than the native mirror operation.
        if visible == 0 {
            return Err(DisplayLayoutError::NoIndependentVisibleOutput);
        }
        for layout in result.values() {
            if let DisplayOutputLayout::Enabled {
                mirror: Some(target),
                x,
                y,
                ..
            } = layout
                && !matches!(
                    result.get(target),
                    Some(DisplayOutputLayout::Enabled { mirror: None, x: root_x, y: root_y, .. })
                        if root_x == x && root_y == y
                )
            {
                return Err(DisplayLayoutError::InvalidMirror);
            }
        }
        if result.len() != observed_ids.len() {
            return Err(DisplayLayoutError::IncompleteTopology);
        }
        Ok(Self {
            topology: observed.topology().clone(),
            outputs: result.into_values().collect(),
        })
    }

    #[must_use]
    pub const fn topology(&self) -> &DisplayTopologyId {
        &self.topology
    }

    #[must_use]
    pub fn outputs(&self) -> &[DisplayOutputLayout] {
        &self.outputs
    }

    /// Equality is not an independent observer: the caller must supply
    /// independently attested, current, exact-source native output state.
    #[must_use]
    pub fn same_exact_layout(&self, independent: &Self) -> bool {
        self == independent
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayLayoutError {
    InvalidEncoding,
    InvalidMode,
    InvalidScale,
    InvalidTransform,
    InvalidSupportedModes,
    DuplicateMode,
    IncompleteTopology,
    AmbiguousOutput,
    ForeignOutput,
    UnsupportedDisable,
    UnsupportedMode,
    InvalidPosition,
    InvalidGeometry,
    InvalidMirror,
    NoIndependentVisibleOutput,
}

impl Display for DisplayLayoutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidEncoding => "display layout encoding is unsupported or noncanonical",
            Self::InvalidMode => "invalid native display mode tuple",
            Self::InvalidScale => "display scale is outside the bounded native range",
            Self::InvalidTransform => "display transform is outside the closed native vocabulary",
            Self::InvalidSupportedModes => "native mode inventory size is invalid",
            Self::DuplicateMode => "native mode inventory contains duplicates",
            Self::IncompleteTopology => "display layout does not cover full observed topology",
            Self::AmbiguousOutput => "display output identity is duplicated",
            Self::ForeignOutput => "display target is not in the current observed topology",
            Self::UnsupportedDisable => "native output cannot be disabled",
            Self::UnsupportedMode => "requested output mode was not independently observed",
            Self::InvalidPosition => "display output position is outside the bounded range",
            Self::InvalidGeometry => "display output geometry is not finite and visible",
            Self::InvalidMirror => {
                "mirror target is missing, disabled, mirrored or has a different origin"
            }
            Self::NoIndependentVisibleOutput => "display layout removes every visible root",
        })
    }
}

impl std::error::Error for DisplayLayoutError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootId, CompositorInvocationId, SessionEpoch};

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn test_outputs() -> (DisplayOutputSet, Vec<NativeOutputCapabilities>) {
        let epoch = id(SessionEpoch::new(
            id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            1000,
            "c2",
            42,
        ));
        let topology = id(DisplayTopologyId::new(
            epoch,
            "seat0",
            id(CompositorInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            7,
        ));
        let one = id(DisplayOutputId::new(topology.clone(), 0, 1));
        let two = id(DisplayOutputId::new(topology.clone(), 7, 9));
        let observed = id(DisplayOutputSet::new(
            topology,
            vec![one.clone(), two.clone()],
        ));
        let mode = id(DisplayMode::new(1920, 1080, 60_000));
        (
            observed,
            vec![
                id(NativeOutputCapabilities::new(one, vec![mode], false)),
                id(NativeOutputCapabilities::new(two, vec![mode], true)),
            ],
        )
    }

    fn enabled(
        output: &DisplayOutputId,
        x: i32,
        mirror: Option<DisplayOutputId>,
    ) -> DisplayOutputLayout {
        DisplayOutputLayout::Enabled {
            output: output.clone(),
            mode: id(DisplayMode::new(1920, 1080, 60_000)),
            scale: id(DisplayScale::new(1000)),
            transform: DisplayTransform::Normal,
            x,
            y: 0,
            mirror,
        }
    }

    #[test]
    fn exact_layout_requires_complete_native_inventory_and_preserves_order() {
        let (observed, caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        let layout = id(DisplayLayout::new(
            &observed,
            &caps,
            vec![enabled(&second, 1920, None), enabled(&first, 0, None)],
        ));
        assert_eq!(layout.outputs().len(), 2);
        assert_eq!(layout.topology(), observed.topology());
        assert_eq!(layout.outputs()[0].output(), &first);
        assert_eq!(
            DisplayLayout::new(&observed, &caps, vec![enabled(&first, 0, None)]),
            Err(DisplayLayoutError::IncompleteTopology)
        );
        assert_eq!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![enabled(&first, 0, None), enabled(&first, 0, None)],
            ),
            Err(DisplayLayoutError::AmbiguousOutput)
        );
    }

    #[test]
    fn native_transforms_are_closed_and_round_trip_without_aliases() {
        for value in 0..8 {
            assert_eq!(
                id(DisplayTransform::from_native(value)).native_value(),
                value
            );
        }
        for value in [8, 90, 180, 270, u32::MAX] {
            assert_eq!(
                DisplayTransform::from_native(value),
                Err(DisplayLayoutError::InvalidTransform)
            );
        }
    }

    #[test]
    fn canonical_layout_binds_full_identity_and_rejects_aliases_or_extra_material() {
        let (observed, caps) = test_outputs();
        let first = &observed.outputs()[0];
        let second = &observed.outputs()[1];
        let layout = id(DisplayLayout::new(
            &observed,
            &caps,
            vec![
                enabled(first, 0, None),
                enabled(second, 0, Some(first.clone())),
            ],
        ));
        let text = id(layout.canonical_text());
        assert!(!text.chars().any(char::is_control));
        assert_eq!(
            id(DisplayLayout::from_canonical_text(&observed, &caps, &text)),
            layout
        );
        for bad in [
            text.replace("LNDL:1", "LNDL:2"),
            text.replace("0:1:enabled", "00:1:enabled"),
            text.replace(":1000:0:0:0:", ":1000:0:+0:0:"),
            format!("{text};"),
            format!("{text}0:1:disabled;"),
            text.trim_end_matches(';').to_owned(),
            text.replace("seat0", "seat1"),
            text.replace("7:9:enabled", "7:10:enabled"),
            "x".repeat(4097),
        ] {
            assert!(
                DisplayLayout::from_canonical_text(&observed, &caps, &bad).is_err(),
                "{bad}"
            );
        }
        let mut rows: Vec<_> = text.trim_end_matches(';').split(';').collect();
        rows.swap(2, 3);
        assert!(
            DisplayLayout::from_canonical_text(&observed, &caps, &(rows.join(";") + ";")).is_err()
        );
    }

    #[test]
    fn geometry_bounds_round_outward_and_rotation_checks_both_axes() {
        let (observed, mut caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        // 16417 / .501 = 32768.463..., which truncation wrongly admitted.
        let mode = id(DisplayMode::new(16_417, 1080, 60_000));
        caps[0] = id(NativeOutputCapabilities::new(
            first.clone(),
            vec![mode],
            false,
        ));
        for transform in [DisplayTransform::Normal, DisplayTransform::Rotate90] {
            let oversized = DisplayOutputLayout::Enabled {
                output: first.clone(),
                mode,
                scale: id(DisplayScale::new(501)),
                transform,
                x: 0,
                y: 0,
                mirror: None,
            };
            assert_eq!(
                DisplayLayout::new(
                    &observed,
                    &caps,
                    vec![oversized, enabled(&second, 1920, None)]
                ),
                Err(DisplayLayoutError::InvalidGeometry)
            );
        }
    }

    #[test]
    fn unsupported_mode_scale_position_and_disablement_fail_closed() {
        let (observed, caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        let different = DisplayOutputLayout::Enabled {
            output: first.clone(),
            mode: id(DisplayMode::new(1280, 720, 60_000)),
            scale: id(DisplayScale::new(1000)),
            transform: DisplayTransform::Normal,
            x: 0,
            y: 0,
            mirror: None,
        };
        assert_eq!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![different, enabled(&second, 1920, None)],
            ),
            Err(DisplayLayoutError::UnsupportedMode)
        );
        assert_eq!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![
                    DisplayOutputLayout::Disabled { output: first },
                    enabled(&second, 1920, None),
                ],
            ),
            Err(DisplayLayoutError::UnsupportedDisable)
        );
        assert!(DisplayScale::new(0).is_err());
        assert!(DisplayScale::new(4001).is_err());
        assert!(DisplayMode::new(0, 1080, 60_000).is_err());
        assert!(DisplayMode::new(1920, 1080, 0).is_err());
    }

    #[test]
    fn sole_visible_output_and_mirror_chain_are_rejected() {
        let (observed, caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        assert_eq!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![
                    enabled(&first, 0, Some(second.clone())),
                    enabled(&second, 0, Some(first.clone())),
                ],
            ),
            Err(DisplayLayoutError::NoIndependentVisibleOutput)
        );
        assert_eq!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![
                    enabled(&first, 0, Some(second.clone())),
                    DisplayOutputLayout::Disabled { output: second },
                ],
            ),
            Err(DisplayLayoutError::NoIndependentVisibleOutput)
        );
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        assert!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![enabled(&first, 0, None), enabled(&second, 0, Some(first))],
            )
            .is_ok()
        );
    }

    #[test]
    fn mirror_origin_must_match_the_enabled_root() {
        let (observed, caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        for x in [-1920, 1920] {
            assert_eq!(
                DisplayLayout::new(
                    &observed,
                    &caps,
                    vec![
                        enabled(&first, 0, None),
                        enabled(&second, x, Some(first.clone()))
                    ],
                ),
                Err(DisplayLayoutError::InvalidMirror)
            );
        }
        let mut mirrored = enabled(&second, 0, Some(first.clone()));
        if let DisplayOutputLayout::Enabled { y, .. } = &mut mirrored {
            *y = 1;
        }
        assert_eq!(
            DisplayLayout::new(&observed, &caps, vec![enabled(&first, 0, None), mirrored]),
            Err(DisplayLayoutError::InvalidMirror)
        );
    }

    #[test]
    fn foreign_generations_and_duplicate_mode_inventory_are_rejected() {
        let (observed, caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        let foreign = id(DisplayOutputId::new(
            observed.topology().clone(),
            second.handle(),
            second.generation() + 1,
        ));
        assert_eq!(
            DisplayLayout::new(
                &observed,
                &caps,
                vec![enabled(&first, 0, None), enabled(&foreign, 1920, None)],
            ),
            Err(DisplayLayoutError::ForeignOutput)
        );
        let mode = id(DisplayMode::new(1920, 1080, 60_000));
        assert_eq!(
            NativeOutputCapabilities::new(first, vec![mode, mode], true),
            Err(DisplayLayoutError::DuplicateMode)
        );
    }

    #[test]
    fn exact_native_postcondition_requires_matching_compositor_topology_and_layout() {
        let (observed, caps) = test_outputs();
        let first = observed.outputs()[0].clone();
        let second = observed.outputs()[1].clone();
        let before = id(DisplayLayout::new(
            &observed,
            &caps,
            vec![enabled(&first, 0, None), enabled(&second, 1920, None)],
        ));
        let after = id(DisplayLayout::new(
            &observed,
            &caps,
            vec![enabled(&first, 0, None), enabled(&second, 0, Some(first))],
        ));
        assert!(before.same_exact_layout(&before));
        assert!(!before.same_exact_layout(&after));
    }
}
